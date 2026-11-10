/******************************************************************************
 *   Copyright (C) 2016 Mathias Hasselmann <mathias.hasselmann@kdab.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include "keychain_p.h"

#include <QDebug>

#include <atomic>
#include <memory>

#import <Foundation/Foundation.h>
#import <Security/Security.h>

using namespace QKeychain;

struct ErrorDescription
{
    QKeychain::Error code;
    QString message;

    ErrorDescription(QKeychain::Error code, const QString &message) : code(code), message(message)
    {
    }

    static ErrorDescription fromStatus(OSStatus status)
    {
        switch (status) {
        case errSecSuccess:
            return ErrorDescription(QKeychain::NoError, Job::tr("No error"));
        case errSecItemNotFound:
            return ErrorDescription(
                    QKeychain::EntryNotFound,
                    Job::tr("The specified item could not be found in the keychain"));
        case errSecUserCanceled:
            return ErrorDescription(QKeychain::AccessDeniedByUser,
                                    Job::tr("User canceled the operation"));
        case errSecInteractionNotAllowed:
            return ErrorDescription(QKeychain::AccessDenied,
                                    Job::tr("User interaction is not allowed"));
        case errSecNotAvailable:
            return ErrorDescription(
                    QKeychain::AccessDenied,
                    Job::tr("No keychain is available. You may need to restart your computer"));
        case errSecAuthFailed:
            return ErrorDescription(
                    QKeychain::AccessDenied,
                    Job::tr("The user name or passphrase you entered is not correct"));
        case errSecVerifyFailed:
            return ErrorDescription(QKeychain::AccessDenied,
                                    Job::tr("A cryptographic verification failure has occurred"));
        case errSecMissingEntitlement:
            return ErrorDescription(QKeychain::AccessDenied,
                                    Job::tr("A required entitlement is not present"));
        case errSecUnimplemented:
            return ErrorDescription(QKeychain::NotImplemented,
                                    Job::tr("Function or operation not implemented"));
        case errSecIO:
            return ErrorDescription(QKeychain::OtherError, Job::tr("I/O error"));
        case errSecOpWr:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Already open with with write permission"));
        case errSecParam:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Invalid parameters passed to a function"));
        case errSecAllocate:
            return ErrorDescription(QKeychain::OtherError, Job::tr("Failed to allocate memory"));
        case errSecBadReq:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Bad parameter or invalid state for operation"));
        case errSecInternalComponent:
            return ErrorDescription(QKeychain::OtherError, Job::tr("An internal component failed"));
        case errSecDuplicateItem:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("The specified item already exists in the keychain"));
        case errSecDecode:
            return ErrorDescription(QKeychain::OtherError,
                                    Job::tr("Unable to decode the provided data"));
        }

        return ErrorDescription(QKeychain::OtherError, Job::tr("Unknown error"));
    }
};

@interface AppleKeychainInterface : NSObject

- (instancetype)initWithJob:(Job *)job andPrivateJob:(JobPrivate *)privateJob;
- (void)keychainTaskFinished;
- (void)keychainReadTaskFinished:(const QByteArray &)retrievedData;
- (void)keychainTaskFinishedWithError:(OSStatus)status
                   descriptiveMessage:(NSString *)descriptiveMessage;

@end

@interface AppleKeychainInterface () {
    QPointer<Job> _job;
    QPointer<JobPrivate> _privateJob;
}
@end

@implementation AppleKeychainInterface

- (instancetype)initWithJob:(Job *)job andPrivateJob:(JobPrivate *)privateJob
{
    self = [super init];
    if (self) {
        _job = job;
        _privateJob = privateJob;
    }
    return self;
}

- (void)dealloc
{
    [NSNotificationCenter.defaultCenter removeObserver:self];
    [super dealloc];
}

- (void)keychainTaskFinished
{
    if (_job) {
        _job->emitFinished();
    }
}

- (void)keychainReadTaskFinished:(const QByteArray &)retrievedData
{
    if (_privateJob) {
        _privateJob->data = retrievedData;
        _privateJob->mode = JobPrivate::Binary;
    }

    if (_job) {
        _job->emitFinished();
    }
}

- (void)keychainTaskFinishedWithError:(OSStatus)status
                   descriptiveMessage:(NSString *)descriptiveMessage
{
    const auto localisedDescriptiveMessage = Job::tr([descriptiveMessage UTF8String]);

    const ErrorDescription error = ErrorDescription::fromStatus(status);
    const auto fullMessage = localisedDescriptiveMessage.isEmpty()
            ? error.message
            : QStringLiteral("%1: %2").arg(localisedDescriptiveMessage, error.message);

    if (_job) {
        _job->emitFinishedWithError(error.code, fullMessage);
    }
}

@end

class Completion {
public:
    Completion(AppleKeychainInterface *const interface, void (^callback)())
        : interface([interface retain]), callback([callback copy])
    {
    }

    ~Completion()
    {
        [interface release];
        [callback release];
    }

    void operator()()
    {
        callback();
    }

private:
    AppleKeychainInterface *const interface;
    void (^callback)();
};

static void dispatchOnQtMainThread(AppleKeychainInterface *const interface, void (^callback)())
{
    auto completion = std::make_shared<Completion>(interface, callback);
    QMetaObject::invokeMethod(qApp, [completion]() {
        (*completion)();
    }, Qt::QueuedConnection);
}

namespace {

// On macOS, there are two keychain implementations: the legacy, file-based keychain and the
// data protection keychain (macOS >= 10.15). On iOS and other Apple platforms, there is only the
// data protection keychain, which is what queries use if kSecUseDataProtectionKeychain isn't set;
// so there we always use KeychainKind::Default.
enum class KeychainKind {
    Default, // the file-based keychain on macOS, the (only) data protection keychain elsewhere
    DataProtection, // the data protection keychain on macOS
};

// Set once the data protection keychain returned errSecMissingEntitlement. Second line of
// defense in case the up-front entitlement check (hasKeychainAccessGroupEntitlement()) passes but
// the data protection keychain still rejects the process. (Entitlements never change at runtime)
std::atomic<bool> s_dataProtectionKeychainMissingEntitlement(false);

#if defined(Q_OS_MACOS)
// Returns true if the process has an entitlement that gives it a keychain access group, which is
// required to use the data protection keychain. Apps without one (unsigned/ad-hoc signed
// development builds, Developer ID builds without provisioning profile) can't use it. We can't
// rely on errSecMissingEntitlement to detect that, as e.g. SecItemCopyMatching returns
// errSecItemNotFound in that case.
bool hasKeychainAccessGroupEntitlement()
{
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) {
        return false;
    }
    const CFStringRef names[] = {
        CFSTR("com.apple.application-identifier"),
        CFSTR("keychain-access-groups"),
        CFSTR("com.apple.security.application-groups"), // app groups are keychain access groups too
    };
    bool found = false;
    for (CFStringRef name : names) {
        CFTypeRef value = SecTaskCopyValueForEntitlement(task, name, nullptr);
        if (value) {
            CFRelease(value);
            found = true;
            break;
        }
    }
    CFRelease(task);
    return found;
}
#endif

bool isDataProtectionKeychainAvailable()
{
#if defined(Q_OS_MACOS)
    if (s_dataProtectionKeychainMissingEntitlement.load()) {
        return false;
    }
    if (@available(macOS 10.15, *)) {
        // Thread-safe one-time initialization (jobs run on a global dispatch queue)
        static const bool hasEntitlement = [] {
            const bool result = hasKeychainAccessGroupEntitlement();
            if (!result) {
                qDebug("QtKeychain: The application has no keychain access group entitlement "
                       "(e.g. no application identifier); using the file-based keychain.");
            }
            return result;
        }();
        return hasEntitlement;
    }
#endif
    return false;
}

// Returns true (and remembers it) if @p status indicates that the data protection keychain
// cannot be used by this process.
bool handleMissingEntitlement(OSStatus status)
{
    if (status != errSecMissingEntitlement) {
        return false;
    }
    if (!s_dataProtectionKeychainMissingEntitlement.exchange(true)) {
        qDebug("QtKeychain: The data protection keychain is not available (missing entitlement, "
               "e.g. the application is not signed with an application identifier). "
               "Falling back to the file-based keychain.");
    }
    return true;
}

bool isRealError(OSStatus status)
{
    return status != errSecSuccess && status != errSecItemNotFound;
}

// Returns an autoreleased dictionary.
NSMutableDictionary *createQuery(const QString &service, const QString &key, KeychainKind kind)
{
    NSMutableDictionary *const query = [NSMutableDictionary dictionaryWithDictionary:@{
        (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrService : service.toNSString(),
        (__bridge NSString *)kSecAttrAccount : key.toNSString(),
    }];

#if defined(Q_OS_MACOS)
    if (@available(macOS 10.15, *)) {
        // Be explicit for the legacy keychain as well (@NO is the documented default)
        query[(__bridge NSString *)kSecUseDataProtectionKeychain] =
                kind == KeychainKind::DataProtection ? @YES : @NO;
    }
#else
    Q_UNUSED(kind)
#endif

    return query;
}

OSStatus readItem(const QString &service, const QString &key, KeychainKind kind,
                  QByteArray *data)
{
    NSMutableDictionary *const query = createQuery(service, key, kind);
    query[(__bridge NSString *)kSecReturnData] = @YES;

    CFTypeRef dataRef = nullptr;
    const OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &dataRef);

    data->clear();
    if (status == errSecSuccess && dataRef) {
        *data = QByteArray::fromNSData((__bridge NSData *)dataRef);
    }
    if (dataRef) {
        CFRelease(dataRef);
    }
    return status;
}

OSStatus writeItem(const QString &service, const QString &key, KeychainKind kind,
                   const QByteArray &data)
{
    NSMutableDictionary *const query = createQuery(service, key, kind);
    NSDictionary *const update = @{
        (__bridge NSString *)kSecValueData : data.toNSData(),
    };

    OSStatus status =
            SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);

    if (status == errSecItemNotFound) {
        query[(__bridge NSString *)kSecValueData] = data.toNSData();
        status = SecItemAdd((__bridge CFDictionaryRef)query, nullptr);
    }

    return status;
}

OSStatus deleteItem(const QString &service, const QString &key, KeychainKind kind)
{
    NSMutableDictionary *const query = createQuery(service, key, kind);
    return SecItemDelete((__bridge CFDictionaryRef)query);
}

// Removes a legacy entry after it was successfully written to the data protection keychain.
// Failure is not fatal for the job, as the data protection keychain entry takes precedence.
void deleteLegacyItem(const QString &service, const QString &key)
{
    const OSStatus status = deleteItem(service, key, KeychainKind::Default);
    if (isRealError(status)) {
        qWarning("QtKeychain: Could not remove entry from the file-based keychain (OSStatus %d)",
                 static_cast<int>(status));
    }
}

// Copies an entry found in the legacy keychain into the data protection keychain and
// removes the legacy entry. Failure is not fatal for the read job.
void migrateToDataProtectionKeychain(const QString &service, const QString &key,
                                     const QByteArray &data)
{
    const OSStatus status = writeItem(service, key, KeychainKind::DataProtection, data);
    if (status == errSecSuccess) {
        deleteLegacyItem(service, key);
    } else if (!handleMissingEntitlement(status)) {
        qWarning("QtKeychain: Could not migrate entry to the data protection keychain "
                 "(OSStatus %d)",
                 static_cast<int>(status));
    }
}

bool useDataProtectionKeychain(MacOSKeychainPreference preference)
{
    return preference != MacOSKeychainPreference::LegacyKeychain
            && isDataProtectionKeychainAvailable();
}

bool useLegacyFallback(MacOSKeychainPreference preference)
{
    return preference == MacOSKeychainPreference::DataProtectionKeychainWithLegacyFallback;
}

OSStatus readPassword(const QString &service, const QString &key,
                      MacOSKeychainPreference preference, QByteArray *data)
{
    if (!useDataProtectionKeychain(preference)) {
        return readItem(service, key, KeychainKind::Default, data);
    }

    const OSStatus status = readItem(service, key, KeychainKind::DataProtection, data);

    if (handleMissingEntitlement(status)) {
        return readItem(service, key, KeychainKind::Default, data);
    }

    if (status == errSecItemNotFound && useLegacyFallback(preference)) {
        const OSStatus legacyStatus = readItem(service, key, KeychainKind::Default, data);
        if (legacyStatus == errSecSuccess) {
            migrateToDataProtectionKeychain(service, key, *data);
        }
        return legacyStatus;
    }

    return status;
}

OSStatus writePassword(const QString &service, const QString &key,
                       MacOSKeychainPreference preference, const QByteArray &data)
{
    if (!useDataProtectionKeychain(preference)) {
        return writeItem(service, key, KeychainKind::Default, data);
    }

    const OSStatus status = writeItem(service, key, KeychainKind::DataProtection, data);

    if (handleMissingEntitlement(status)) {
        return writeItem(service, key, KeychainKind::Default, data);
    }

    if (status == errSecSuccess && useLegacyFallback(preference)) {
        // Otherwise a stale legacy entry would be returned again after deletion
        deleteLegacyItem(service, key);
    }

    return status;
}

OSStatus deletePassword(const QString &service, const QString &key,
                        MacOSKeychainPreference preference)
{
    if (!useDataProtectionKeychain(preference)) {
        return deleteItem(service, key, KeychainKind::Default);
    }

    const OSStatus status = deleteItem(service, key, KeychainKind::DataProtection);

    if (handleMissingEntitlement(status)) {
        return deleteItem(service, key, KeychainKind::Default);
    }

    if (!useLegacyFallback(preference)) {
        return status;
    }

    const OSStatus legacyStatus = deleteItem(service, key, KeychainKind::Default);

    // Report real errors first (an entry left behind would be found again on read), then
    // success if the entry existed in either keychain, else errSecItemNotFound.
    if (isRealError(status)) {
        return status;
    }
    if (isRealError(legacyStatus)) {
        return legacyStatus;
    }
    if (status == errSecSuccess || legacyStatus == errSecSuccess) {
        return errSecSuccess;
    }
    return errSecItemNotFound;
}

} // namespace

static void StartReadPassword(const QString &service, const QString &key,
                              MacOSKeychainPreference preference,
                              AppleKeychainInterface *const interface)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        @autoreleasepool {
            QByteArray data;
            const OSStatus status = readPassword(service, key, preference, &data);

            if (status == errSecSuccess) {
                dispatchOnQtMainThread(interface, ^{
                    [interface keychainReadTaskFinished:data];
                    [interface release];
                });
            } else {
                NSString *const descriptiveErrorString =
                        @"Could not retrieve private key from keystore";
                dispatchOnQtMainThread(interface, ^{
                    [interface keychainTaskFinishedWithError:status
                                          descriptiveMessage:descriptiveErrorString];
                    [interface release];
                });
            }
        }
    });
}

static void StartWritePassword(const QString &service, const QString &key, const QByteArray &data,
                               MacOSKeychainPreference preference,
                               AppleKeychainInterface *const interface)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        @autoreleasepool {
            const OSStatus status = writePassword(service, key, preference, data);

            if (status == errSecSuccess) {
                dispatchOnQtMainThread(interface, ^{
                    [interface keychainTaskFinished];
                    [interface release];
                });
            } else {
                NSString *const descriptiveErrorString = @"Could not store data in settings";

                dispatchOnQtMainThread(interface, ^{
                    [interface keychainTaskFinishedWithError:status
                                          descriptiveMessage:descriptiveErrorString];
                    [interface release];
                });
            }
        }
    });
}

static void StartDeletePassword(const QString &service, const QString &key,
                                MacOSKeychainPreference preference,
                                AppleKeychainInterface *const interface)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        @autoreleasepool {
            const OSStatus status = deletePassword(service, key, preference);

            if (status == errSecSuccess) {
                dispatchOnQtMainThread(interface, ^{
                    [interface keychainTaskFinished];
                    [interface release];
                });
            } else {
                NSString *const descriptiveErrorString =
                        @"Could not remove private key from keystore";
                dispatchOnQtMainThread(interface, ^{
                    [interface keychainTaskFinishedWithError:status
                                          descriptiveMessage:descriptiveErrorString];
                    [interface release];
                });
            }
        }
    });
}

void ReadPasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartReadPassword(service, key, macOSKeychainPreference, interface);
}

void WritePasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartWritePassword(service, key, data, macOSKeychainPreference, interface);
}

void DeletePasswordJobPrivate::scheduledStart()
{
    AppleKeychainInterface *const interface = [[AppleKeychainInterface alloc] initWithJob:q
                                                                            andPrivateJob:this];
    StartDeletePassword(service, key, macOSKeychainPreference, interface);
}

bool QKeychain::isAvailable()
{
    return true;
}
