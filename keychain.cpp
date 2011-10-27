/******************************************************************************
 *   Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain.h"
#include "keychain_p.h"

using namespace QKeychain;

Keychain::Keychain( const QString& service )
    : d( new Private( service ) )
{
}

Keychain::~Keychain() {
    delete d;
}

QString Keychain::service() const {
    return d->service;
}

Keychain::Error Keychain::error() const {
    return d->error;
}

QString Keychain::errorString() const {
    return d->errorString;
}

void Keychain::writePassword( const QString& account, const QString& password, OverwriteMode om ) {
    QString err;
    const Error ret = d->writePasswordImpl( account, password, om, &err );
    d->error = ret;
    d->errorString = err;
}

QString Keychain::readPassword( const QString& account ) {
    QString err;
    QString pw;
    const Error ret = d->readPasswordImpl( &pw, account, &err );
    d->error = ret;
    d->errorString = err;
    if ( ret != NoError )
        return QString();
    else
        return pw;
}

void Keychain::deletePassword( const QString& account ) {
    QString err;
    const Error ret = d->deletePasswordImpl( account, &err );
    d->error = ret;
    d->errorString = err;
}
