/******************************************************************************
 *   Copyright (C) 2016 Mathias Hasselmann <mathias.hasselmann@kdab.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include "keychain_p.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

using namespace QKeychain;

NSString * const AppleKeychainTaskFinished = @"AppleKeychainTaskFinished";
NSString * const AppleKeychainReadTaskFinished = @"AppleKeychainReadTaskFinished";
NSString * const AppleKeychainTaskFinishedWithError = @"AppleKeychainTaskFinishedWithError";

NSString * const KeychainNotificationUserInfoStatusKey = @"status";
NSString * const KeychainNotificationUserInfoDataKey = @"data";
NSString * const KeychainNotificationUserInfoDescriptiveErrorKey = @"descriptiveError";
NSString * const KeychainNotificationUserInfoNotificationId = @"notificationId";

namespace {
    static unsigned int currentNotificationId = 0;
}

struct ErrorDescription
{
    QKeychain::Error code;
    QString message;

    ErrorDescription(QKeychain::Error code, const QString &message)
        : code(code), message(message) {}

    static ErrorDescription fromStatus(OSStatus status)
    {
        switch(status) {
        case errSecSuccess:
            return ErrorDescription(QKeychain::NoError, Job::tr("No error"));
        case errSecItemNotFound:
            return ErrorDescription(QKeychain::EntryNotFound, Job::tr("The specified item could not be found in the keychain"));
        case errSecUserCanceled:
            return ErrorDescription(QKeychain::AccessDeniedByUser, Job::tr("User canceled the operation"));
        case errSecInteractionNotAllowed:
            return ErrorDescription(QKeychain::AccessDenied, Job::tr("User interaction is not allowed"));
        case errSecNotAvailable:
            return ErrorDescription(QKeychain::AccessDenied, Job::tr("No keychain is available. You may need to restart your computer"));
        case errSecAuthFailed:
            return ErrorDescription(QKeychain::AccessDenied, Job::tr("The user name or passphrase you entered is not correct"));
        case errSecVerifyFailed:
            return ErrorDescription(QKeychain::AccessDenied, Job::tr("A cryptographic verification failure has occurred"));
        case errSecUnimplemented:
            return ErrorDescription(QKeychain::NotImplemented, Job::tr("Function or operation not implemented"));
        case errSecIO:
            return ErrorDescription(QKeychain::OtherError, Job::tr("I/O error"));
        case errSecOpWr:
            return ErrorDescription(QKeychain::OtherError, Job::tr("Already open with with write permission"));
        case errSecParam:
            return ErrorDescription(QKeychain::OtherError, Job::tr("Invalid parameters passed to a function"));
        case errSecAllocate:
            return ErrorDescription(QKeychain::OtherError, Job::tr("Failed to allocate memory"));
        case errSecBadReq:
            return ErrorDescription(QKeychain::OtherError, Job::tr("Bad parameter or invalid state for operation"));
        case errSecInternalComponent:
            return ErrorDescription(QKeychain::OtherError, Job::tr("An internal component failed"));
        case errSecDuplicateItem:
            return ErrorDescription(QKeychain::OtherError, Job::tr("The specified item already exists in the keychain"));
        case errSecDecode:
            return ErrorDescription(QKeychain::OtherError, Job::tr("Unable to decode the provided data"));
        }

        return ErrorDescription(QKeychain::OtherError, Job::tr("Unknown error"));
    }
};

@interface AppleKeychainInterface : NSObject

- (instancetype)initWithJob:(Job *)job andPrivateJob:(JobPrivate *)privateJob andNotificationId:(unsigned int)notificationId;

@end

@interface AppleKeychainInterface()
{
    QPointer<Job> _job;
    QPointer<JobPrivate> _privateJob;
    unsigned int _notificationId;
}
@end

@implementation AppleKeychainInterface

- (instancetype)initWithJob:(Job *)job andPrivateJob:(JobPrivate *)privateJob andNotificationId:(unsigned int)notificationId
{
    self = [super init];
    if (self) {
        _job = job;
        _privateJob = privateJob;
        _notificationId = notificationId;

        NSNotificationCenter * const notificationCenter = NSNotificationCenter.defaultCenter;
        [notificationCenter addObserver:self
                               selector:@selector(keychainTaskFinished:)
                                   name:AppleKeychainTaskFinished
                                 object:nil];
        [notificationCenter addObserver:self
                               selector:@selector(keychainReadTaskFinished:)
                                   name:AppleKeychainReadTaskFinished
                                 object:nil];
        [notificationCenter addObserver:self
                               selector:@selector(keychainTaskFinishedWithError:)
                                   name:AppleKeychainTaskFinishedWithError
                                 object:nil];
    }
    return self;
}

- (void)dealloc
{
    [NSNotificationCenter.defaultCenter removeObserver:self];
    [super dealloc];
}

- (void)keychainTaskFinished:(NSNotification *)notification
{
    NSParameterAssert(notification);
    NSDictionary * const userInfo = notification.userInfo;
    NSAssert(userInfo, @"Keychain task finished with error notification should contain nonnull user info dictionary");

    NSNumber * const retrievedNotificationId = (NSNumber *)[userInfo objectForKey:KeychainNotificationUserInfoNotificationId];
    if (retrievedNotificationId.unsignedIntValue != _notificationId) {
        return;
    }

    if (_job) {
        _job->emitFinished();
    }

    [self release];
}

- (void)keychainReadTaskFinished:(NSNotification *)notification
{
    NSParameterAssert(notification);
    NSDictionary * const userInfo = notification.userInfo;
    NSAssert(userInfo, @"Keychain task finished with error notification should contain nonnull user info dictionary");

    NSNumber * const retrievedNotificationId = (NSNumber *)[userInfo objectForKey:KeychainNotificationUserInfoNotificationId];
    if (retrievedNotificationId.unsignedIntValue != _notificationId) {
        return;
    }

    _privateJob->data.clear();
    _privateJob->mode = JobPrivate::Binary;

    NSData * const retrievedData = (NSData *)[userInfo objectForKey:KeychainNotificationUserInfoDataKey];
    if (retrievedData != nil) {
        if (_privateJob) {
            _privateJob->data = QByteArray::fromNSData(retrievedData);
        }
    }

    if (_job) {
        _job->emitFinished();
    }

    [self release];
}

- (void)keychainTaskFinishedWithError:(NSNotification *)notification
{
    NSParameterAssert(notification);
    NSDictionary * const userInfo = notification.userInfo;
    NSAssert(userInfo, @"Keychain task finished with error notification should contain nonnull user info dictionary");

    NSNumber * const retrievedNotificationId = (NSNumber *)[userInfo objectForKey:KeychainNotificationUserInfoNotificationId];
    if (retrievedNotificationId.unsignedIntValue != _notificationId) {
        return;
    }

    NSNumber * const statusNumber = (NSNumber *)[userInfo objectForKey:KeychainNotificationUserInfoStatusKey];
    NSAssert(statusNumber, @"Keychain task notification user info dict should contain valid status number");
    const OSStatus status = statusNumber.intValue;

    NSString * const descriptiveMessage = (NSString *)[userInfo objectForKey:KeychainNotificationUserInfoDescriptiveErrorKey];
    const auto localisedDescriptiveMessage = Job::tr([descriptiveMessage UTF8String]);

    const ErrorDescription error = ErrorDescription::fromStatus(status);
    const auto fullMessage = localisedDescriptiveMessage.isEmpty() ? error.message : QStringLiteral("%1: %2").arg(localisedDescriptiveMessage, error.message);

    if (_job) {
        _job->emitFinishedWithError(error.code, fullMessage);
    }

    [self release];
}

@end


static void StartReadPassword(const QString &service, const QString &key, const unsigned int notificationId)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSNumber * const notificationIdNumber = [NSNumber numberWithUnsignedInt:notificationId];

        NSDictionary * const query = @{
            (__bridge NSString *)kSecClass: (__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService: service.toNSString(),
            (__bridge NSString *)kSecAttrAccount: key.toNSString(),
            (__bridge NSString *)kSecReturnData: @YES,
        };

        CFTypeRef dataRef = nil;
        const OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) query, &dataRef);

        if (status == errSecSuccess) {
            const CFDataRef castedDataRef = (CFDataRef)dataRef;
            NSData * const data = [NSData dataWithBytes:CFDataGetBytePtr(castedDataRef) length:CFDataGetLength(castedDataRef)];
            dispatch_async(dispatch_get_main_queue(), ^{
                [NSNotificationCenter.defaultCenter postNotificationName:AppleKeychainReadTaskFinished
                                                                  object:nil
                                                                userInfo:@{ KeychainNotificationUserInfoDataKey: data,
                                                                            KeychainNotificationUserInfoNotificationId: notificationIdNumber }];
            });
        } else {
            NSNumber * const statusNumber = [NSNumber numberWithInt:status];
            NSString * const descriptiveErrorString = @"Could not retrieve private key from keystore";
            dispatch_async(dispatch_get_main_queue(), ^{
                [NSNotificationCenter.defaultCenter postNotificationName:AppleKeychainTaskFinishedWithError
                                                                  object:nil
                                                                userInfo:@{ KeychainNotificationUserInfoStatusKey: statusNumber,
                                                                            KeychainNotificationUserInfoDescriptiveErrorKey: descriptiveErrorString,
                                                                            KeychainNotificationUserInfoNotificationId: notificationIdNumber }];
            });
        }

         if (dataRef) {
             CFRelease(dataRef);
         }
    });
}

static void StartWritePassword(const QString &service, const QString &key, const QByteArray &data, const unsigned int notificationId)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSNumber * const notificationIdNumber = [NSNumber numberWithUnsignedInt:notificationId];

        NSDictionary * const query = @{
                (__bridge NSString *)kSecClass: (__bridge NSString *)kSecClassGenericPassword,
                (__bridge NSString *)kSecAttrService: service.toNSString(),
                (__bridge NSString *)kSecAttrAccount: key.toNSString(),
        };

        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, nil);

        if (status == errSecSuccess) {
            NSDictionary * const update = @{
                    (__bridge NSString *)kSecValueData: data.toNSData(),
            };

            status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
        } else {
            NSDictionary * const insert = @{
                    (__bridge NSString *)kSecClass: (__bridge NSString *)kSecClassGenericPassword,
                    (__bridge NSString *)kSecAttrService: service.toNSString(),
                    (__bridge NSString *)kSecAttrAccount: key.toNSString(),
                    (__bridge NSString *)kSecValueData: data.toNSData(),
            };

            status = SecItemAdd((__bridge const CFDictionaryRef)insert, nil);
        }

        if (status == errSecSuccess) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [NSNotificationCenter.defaultCenter postNotificationName:AppleKeychainTaskFinished
                                                                  object:nil
                                                                userInfo:@{ KeychainNotificationUserInfoNotificationId: notificationIdNumber }];
            });
        } else {
            NSNumber * const statusNumber = [NSNumber numberWithInt:status];
            NSString * const descriptiveErrorString = @"Could not store data in settings";

            dispatch_async(dispatch_get_main_queue(), ^{
                [NSNotificationCenter.defaultCenter postNotificationName:AppleKeychainTaskFinishedWithError
                                                                  object:nil
                                                                userInfo:@{ KeychainNotificationUserInfoStatusKey: statusNumber,
                                                                            KeychainNotificationUserInfoDescriptiveErrorKey: descriptiveErrorString,
                                                                            KeychainNotificationUserInfoNotificationId: notificationIdNumber }];
            });
        }
    });
}

static void StartDeletePassword(const QString &service, const QString &key, const unsigned int notificationId)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSNumber * const notificationIdNumber = [NSNumber numberWithUnsignedInt:notificationId];

        NSDictionary * const query = @{
            (__bridge NSString *)kSecClass: (__bridge NSString *)kSecClassGenericPassword,
            (__bridge NSString *)kSecAttrService: service.toNSString(),
            (__bridge NSString *)kSecAttrAccount: key.toNSString(),
        };

        const OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

        if (status == errSecSuccess) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [NSNotificationCenter.defaultCenter postNotificationName:AppleKeychainTaskFinished
                                                                  object:nil
                                                                userInfo:@{ KeychainNotificationUserInfoNotificationId: notificationIdNumber }];
            });
        } else {
            NSNumber * const statusNumber = [NSNumber numberWithInt:status];
            NSString * const descriptiveErrorString = @"Could not remove private key from keystore";
            dispatch_async(dispatch_get_main_queue(), ^{
                [NSNotificationCenter.defaultCenter postNotificationName:AppleKeychainTaskFinishedWithError
                                                                  object:nil
                                                                userInfo:@{ KeychainNotificationUserInfoStatusKey: statusNumber,
                                                                            KeychainNotificationUserInfoDescriptiveErrorKey: descriptiveErrorString,
                                                                            KeychainNotificationUserInfoNotificationId: notificationIdNumber }];
            });
        }
    });
}

void ReadPasswordJobPrivate::scheduledStart()
{
    const auto notificationId = ++currentNotificationId;
    [[AppleKeychainInterface alloc] initWithJob:q andPrivateJob:this andNotificationId:notificationId];
    StartReadPassword(service, key, currentNotificationId);
}

void WritePasswordJobPrivate::scheduledStart()
{
    const auto notificationId = ++currentNotificationId;
    [[AppleKeychainInterface alloc] initWithJob:q andPrivateJob:this andNotificationId:notificationId];
    StartWritePassword(service, key, data, currentNotificationId);
}

void DeletePasswordJobPrivate::scheduledStart()
{
    const auto notificationId = ++currentNotificationId;
    [[AppleKeychainInterface alloc] initWithJob:q andPrivateJob:this andNotificationId:notificationId];
    StartDeletePassword(service, key, currentNotificationId);
}
