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

void Keychain::writePassword( const QString &key, const QString &password ) {
    writeEntry( key, password.toUtf8() );
}

void Keychain::writeEntry( const QString& key, const QByteArray& ba ) {
    QString err;
    const Error ret = d->writeEntryImpl( key, ba, &err );
    d->error = ret;
    d->errorString = err;
}

QString Keychain::readPassword( const QString& key ) {
    const QByteArray ba = readEntry( key );
    return QString::fromUtf8( ba.constData(), ba.size() );
}

QByteArray Keychain::readEntry( const QString& key ) {
    QString err;
    QByteArray pw;
    const Error ret = d->readEntryImpl( &pw, key, &err );
    d->error = ret;
    d->errorString = err;
    if ( ret != NoError )
        return QByteArray();
    else
        return pw;
}

bool Keychain::entryExists( const QString& key ) {
    QString err;
    bool exists = false;
    const Error ret = d->entryExistsImpl( &exists, key, &err );
    d->error = ret;
    d->errorString = err;
    return exists;
}

void Keychain::deleteEntry( const QString& key ) {
    QString err;
    const Error ret = d->deleteEntryImpl( key, &err );
    d->error = ret;
    d->errorString = err;
}
