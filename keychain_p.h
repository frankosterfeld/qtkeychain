/******************************************************************************
 *   Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#ifndef KEYCHAIN_P_H
#define KEYCHAIN_P_H

#include <QCoreApplication>

#include "keychain.h"

namespace QKeychain {
class Keychain::Private {
    Q_DECLARE_TR_FUNCTIONS(Keychain::Private)
public:
    explicit Private( const QString& s ) : service( s ) {}

    Keychain::Error writePasswordImpl( const QString& account,
                                       const QString& password,
                                       Keychain::OverwriteMode,
                                       QString* errorString );
    Keychain::Error deletePasswordImpl( const QString& account,
                                        QString* errorString );
    Keychain::Error readPasswordImpl( QString* password,
                                      const QString& account,
                                      QString* errorString );

    const QString service;
    Keychain::Error error;
    QString errorString;
};

}

#endif // KEYCHAIN_P_H
