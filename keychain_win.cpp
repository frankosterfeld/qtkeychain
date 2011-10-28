/******************************************************************************
 *   Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"

using namespace QKeychain;

Keychain::Error Keychain::Private::readEntryImpl( QByteArray* pw,
                                                  const QString& account,
                                                  QString* err ) {
    Q_ASSERT( pw );
    Q_ASSERT( err );
    err->clear();
    *err = tr("Not implemented");
    return OtherError;
}

Keychain::Error Keychain::Private::writeEntryImpl( const QString& account,
                                                   const QByteArray& data,
                                                   QString* err ) {
    Q_ASSERT( err );
    err->clear();
    *err = tr("Not implemented");
    return OtherError;
}

Keychain::Error Keychain::Private::deleteEntryImpl( const QString& account,
                                                    QString* err ) {
    Q_ASSERT( err );
    err->clear();
    *err = tr("Not implemented");
    return OtherError;
}


Keychain::Error Keychain::Private::entryExistsImpl( bool* exists,
                                                    const QString& account,
                                                    QString* err ) {
    Q_ASSERT( exists );
    Q_ASSERT( err );
    err->clear();
    *err = tr("Not implemented");
    return OtherError;
}
