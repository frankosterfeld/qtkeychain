/******************************************************************************
 *   Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"

QString Keychain::Private::readPasswordImpl( const QString& account ) const {
    throw KeychainException( QLatin1String("not implemented") );
}

void Keychain::Private::writePasswordImpl( const QString& account, const QString& password ) {
    throw KeychainException( QLatin1String("not implemented") );
}

