/******************************************************************************
 *   Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"

#include <QSettings>

#include <Windows.h>
#include <WinCrypt.h>

using namespace QKeychain;

Keychain::Error Keychain::Private::readEntryImpl( QByteArray* pw,
                                                  const QString& key,
                                                  QString* err ) {
    Q_ASSERT( pw );
    Q_ASSERT( err );
    err->clear();

    QSettings settings( service );
    QByteArray encrypted = settings.value( key ).toByteArray();
    if ( encrypted.isNull() ) {
        *err = tr("Entry not found");
        return EntryNotFound;
    }

    DATA_BLOB blob_in, blob_out;

    blob_in.pbData = reinterpret_cast<BYTE*>( encrypted.data() );
    blob_in.cbData = encrypted.size();

    const BOOL ret = CryptUnprotectData( &blob_in,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         0,
                                         &blob_out );
    if ( !ret ) {
        *err = tr("Could not decrypt data");
        return OtherError;
    }
    *pw = QByteArray( reinterpret_cast<char*>( blob_out.pbData ), blob_out.cbData );
    SecureZeroMemory( blob_out.pbData, blob_out.cbData );
    LocalFree( blob_out.pbData );
    return NoError;
}

Keychain::Error Keychain::Private::writeEntryImpl( const QString& key,
                                                   const QByteArray& data_,
                                                   QString* err ) {
    Q_ASSERT( err );
    err->clear();
    QByteArray data = data_;
    DATA_BLOB blob_in, blob_out;
    blob_in.pbData = reinterpret_cast<BYTE*>( data.data() );
    blob_in.cbData = data.size();
    const BOOL res = CryptProtectData( &blob_in,
                                       L"QKeychain-encrypted data",
                                       NULL,
                                       NULL,
                                       NULL,
                                       0,
                                       &blob_out );
    if ( !res ) {
        *err = tr("Encryption failed"); //TODO more details available?
        return OtherError;
    }

    const QByteArray encrypted( reinterpret_cast<char*>( blob_out.pbData ), blob_out.cbData );
    LocalFree( blob_out.pbData );

    QSettings settings( service );
    settings.setValue( key, encrypted );
    settings.sync();
    if ( settings.status() != QSettings::NoError ) {
        *err = settings.status() == QSettings::AccessError
                ? tr("Could not store encrypted data in settings: access error")
                : tr("Could not store encrypted data in settings: format error");
        return OtherError;
    }

    return NoError;
}

Keychain::Error Keychain::Private::deleteEntryImpl( const QString& key,
                                                    QString* err ) {
    Q_ASSERT( err );
    err->clear();
    QSettings settings( service );
    settings.remove( key );
    settings.sync();
    if ( settings.status() != QSettings::NoError ) {
        *err = settings.status() == QSettings::AccessError
                ? tr("Could not delete encrypted data from settings: access error")
                : tr("Could not delete encrypted data from settings: format error");
        return OtherError;
    }

    return NoError;
}


Keychain::Error Keychain::Private::entryExistsImpl( bool* exists,
                                                    const QString& key,
                                                    QString* err ) {
    Q_ASSERT( exists );
    Q_ASSERT( err );
    err->clear();
    *exists = false;
    QSettings settings( service );
    const bool ex = settings.contains( key );
    if ( settings.status() != QSettings::NoError ) {
        *err = settings.status() == QSettings::AccessError
                ? tr("Could not read settings: access error")
                : tr("Could not read settings: format error");
        return OtherError;
    }

    *exists = ex;
    return NoError;
}
