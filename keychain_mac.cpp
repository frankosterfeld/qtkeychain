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

static OSStatus readPw( QString* pw,
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
        *pw = QString::fromUtf8( reinterpret_cast<const char*>( data ), len );
        const OSStatus ret2 = SecKeychainItemFreeContent ( 0, data );
        if ( ret2 != noErr )
            qWarning() << "Could not free item content: " << strForStatus( ret2 );
    }
    return ret;
}

Keychain::Error Keychain::Private::readPasswordImpl( QString* pw,
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
        return PasswordNotFound;
    default:
        *err = strForStatus( ret );
        return OtherError;
    }
}

Keychain::Error Keychain::Private::writePasswordImpl( const QString& account,
                                                      const QString& password,
                                                      Keychain::OverwriteMode ov,
                                                      QString* err ) {
    Q_ASSERT( err );
    err->clear();
    const QByteArray serviceData = service.toUtf8();
    const QByteArray accountData = account.toUtf8();
    const QByteArray passwordData = password.toUtf8();
    const OSStatus ret = SecKeychainAddGenericPassword( NULL, //default keychain
                                                        serviceData.size(),
                                                        serviceData.constData(),
                                                        accountData.size(),
                                                        accountData.constData(),
                                                        passwordData.size(),
                                                        passwordData.constData(),
                                                        NULL //item reference
                                                        );
    if ( ret != noErr ) {
        switch ( ret ) {
        case errSecDuplicateItem:
        {
            if ( ov == Keychain::DoNotOverwrite ) {
                *err = tr("Entry already exists");
                return EntryAlreadyExists;
            }
            Error derr = deletePasswordImpl( account, err );
            if ( derr != NoError )
                return CouldNotDeletePassword;
            else
                return writePasswordImpl( account, password, ov, err );
        }
        default:
            *err = strForStatus( ret );
            return OtherError;
        }
    }

    return NoError;
}

Keychain::Error Keychain::Private::deletePasswordImpl( const QString& account,
                                                       QString* err ) {
    SecKeychainItemRef ref;
    QString pw;
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
    return CouldNotDeletePassword;
}

