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

using namespace QKeychain;

Keychain::Error Keychain::Private::readEntryImpl( QByteArray* pw,
                                                  const QString& key,
                                                  QString* err ) {
    Q_UNUSED( key )
    Q_ASSERT( pw );
    Q_ASSERT( err );
    return NotImplemented;
}

Keychain::Error Keychain::Private::writeEntryImpl( const QString& key,
                                                   const QByteArray& data_,
                                                   QString* err ) {
    Q_ASSERT( err );
    return NotImplemented;
}

Keychain::Error Keychain::Private::deleteEntryImpl( const QString& key,
                                                    QString* err ) {
    Q_ASSERT( err );
    err->clear();
    return NotImplemented;
}


Keychain::Error Keychain::Private::entryExistsImpl( bool* exists,
                                                    const QString& key,
                                                    QString* err ) {
    Q_ASSERT( exists );
    Q_ASSERT( err );
    err->clear();
    *exists = false;
    return NotImplemented;
}
