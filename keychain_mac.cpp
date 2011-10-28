/******************************************************************************
 *   Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <QDebug>

using namespace QKeychain;

template <typename T>
struct Releaser {
    explicit Releaser( const T& v ) : value( v ) {}
    ~Releaser() {
        CFRelease( value );
    }

    const T value;
};

static QString strForStatus( OSStatus os ) {
    const Releaser<CFStringRef> str( SecCopyErrorMessageString( os, 0 ) );
    const char * const buf = CFStringGetCStringPtr( str.value,  kCFStringEncodingUTF8 );
    if ( !buf )
        return QString();
    return QString::fromUtf8( buf, strlen( buf ) );
}

static OSStatus readPw( QByteArray* pw,
                        const QString& service,
                        const QString& account,
                        SecKeychainItemRef* ref ) {
    Q_ASSERT( pw );
    pw->clear();
    const QByteArray serviceData = service.toUtf8();
    const QByteArray accountData = account.toUtf8();

    void* data = 0;
    UInt32 len = 0;

    const OSStatus ret = SecKeychainFindGenericPassword( NULL, // default keychain
                                                         serviceData.size(),
                                                         serviceData.constData(),
                                                         accountData.size(),
                                                         accountData.constData(),
                                                         &len,
                                                         &data,
                                                         ref );
    if ( ret == noErr ) {
        *pw = QByteArray( reinterpret_cast<const char*>( data ), len );
        const OSStatus ret2 = SecKeychainItemFreeContent ( 0, data );
        if ( ret2 != noErr )
            qWarning() << "Could not free item content: " << strForStatus( ret2 );
    }
    return ret;
}

Keychain::Error Keychain::Private::readEntryImpl( QByteArray* pw,
                                                  const QString& account,
                                                  QString* err ) {
    Q_ASSERT( pw );
    Q_ASSERT( err );
    err->clear();
    const OSStatus ret = readPw( pw, service, account, 0 );
    switch ( ret ) {
    case noErr:
        return NoError;
    case errSecItemNotFound:
        *err = tr("Password not found");
        return EntryNotFound;
    default:
        *err = strForStatus( ret );
        return OtherError;
    }
}

Keychain::Error Keychain::Private::writeEntryImpl( const QString& account,
                                                   const QByteArray& data,
                                                   QString* err ) {
    Q_ASSERT( err );
    err->clear();
    const QByteArray serviceData = service.toUtf8();
    const QByteArray accountData = account.toUtf8();
    const OSStatus ret = SecKeychainAddGenericPassword( NULL, //default keychain
                                                        serviceData.size(),
                                                        serviceData.constData(),
                                                        accountData.size(),
                                                        accountData.constData(),
                                                        data.size(),
                                                        data.constData(),
                                                        NULL //item reference
                                                        );
    if ( ret != noErr ) {
        switch ( ret ) {
        case errSecDuplicateItem:
        {
            Error derr = deleteEntryImpl( account, err );
            if ( derr != NoError )
                return CouldNotDeleteEntry;
            else
                return writeEntryImpl( account, data, err );
        }
        default:
            *err = strForStatus( ret );
            return OtherError;
        }
    }

    return NoError;
}

Keychain::Error Keychain::Private::deleteEntryImpl( const QString& account,
                                                    QString* err ) {
    SecKeychainItemRef ref;
    QByteArray pw;
    const OSStatus ret1 = readPw( &pw, service, account, &ref );
    if ( ret1 == errSecItemNotFound )
        return NoError; // No item stored, we're done
    if ( ret1 != noErr ) {
        *err = strForStatus( ret1 );
        //TODO map error code, set errstr
        return OtherError;
    }
    const Releaser<SecKeychainItemRef> releaser( ref );

    const OSStatus ret2 = SecKeychainItemDelete( ref );

    if ( ret2 == noErr )
        return NoError;
    //TODO map error code
    *err = strForStatus( ret2 );
    return CouldNotDeleteEntry;
}


Keychain::Error Keychain::Private::entryExistsImpl( bool* exists,
                                                    const QString& account,
                                                    QString* err ) {
    Q_ASSERT( exists );
    *exists = false;
    SecKeychainItemRef ref;
    QByteArray pw;
    const OSStatus ret1 = readPw( &pw, service, account, &ref );
    if ( ret1 == errSecItemNotFound ) {
        return NoError;
    }
    if ( ret1 != noErr ) {
        *err = strForStatus( ret1 );
        //TODO map error code, set errstr
        return OtherError;
    }

    CFRelease( ref );
    *exists = true;
    return NoError;
}
