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

Job::Job( const QString& service, QObject *parent )
    : QObject( parent )
    , d ( new Private( service ) ) {
}

Job::~Job() {
    delete d;
}

QString Job::service() const {
    return d->service;
}

QSettings* Job::settings() const {
    return d->settings;
}

void Job::setSettings( QSettings* settings ) {
    d->settings = settings;
}

void Job::start() {
    QMetaObject::invokeMethod( this, "doStart", Qt::QueuedConnection );
}

bool Job::autoDelete() const {
    return d->autoDelete;
}

void Job::setAutoDelete( bool autoDelete ) {
    d->autoDelete = autoDelete;
}

void Job::emitFinished() {
    emit finished( this );
    if ( d->autoDelete )
        deleteLater();
}

void Job::emitFinishedWithError( Error error, const QString& errorString ) {
    d->error = error;
    d->errorString = errorString;
    emitFinished();
}

Error Job::error() const {
    return d->error;
}

QString Job::errorString() const {
    return d->errorString;
}

void Job::setError( Error error ) {
    d->error = error;
}

void Job::setErrorString( const QString& errorString ) {
    d->errorString = errorString;
}

ReadPasswordJob::ReadPasswordJob( const QString& service, QObject* parent )
    : Job( service, parent )
    , d( new Private( this ) )
{}

ReadPasswordJob::~ReadPasswordJob() {
    delete d;
}

QString ReadPasswordJob::textData() const {
    return QString::fromUtf8( d->data );
}

QByteArray ReadPasswordJob::binaryData() const {
    return d->data;
}

QString ReadPasswordJob::key() const {
    return d->key;
}

void ReadPasswordJob::setKey( const QString& key ) {
    d->key = key;
}

void ReadPasswordJob::doStart() {
    d->doStart();
}

WritePasswordJob::WritePasswordJob( const QString& service, QObject* parent )
    : Job( service, parent )
    , d( new Private( this ) ) {
}

WritePasswordJob::~WritePasswordJob() {
    delete d;
}

QString WritePasswordJob::key() const {
    return d->key;
}

void WritePasswordJob::setKey( const QString& key ) {
    d->key = key;
}

void WritePasswordJob::setBinaryData( const QByteArray& data ) {
    d->binaryData = data;
    d->mode = Private::Binary;
}

void WritePasswordJob::setTextData( const QString& data ) {
    d->textData = data;
    d->mode = Private::Text;
}

void WritePasswordJob::doStart() {
    d->doStart();
}

#if 0
Keychain::Keychain( const QString& service, QSettings* settings )
    : d( new Private( service, settings ) ) {
    Q_ASSERT( !service.isEmpty() );
}

Keychain::~Keychain() {
    delete d;
}

QString Keychain::service() const {
    return d->service;
}

QKeychain::Error Keychain::error() const {
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

#endif
