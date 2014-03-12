/******************************************************************************
 *   Copyright (C) 2011-2014 Frank Osterfeld <frank.osterfeld@gmail.com>      *
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
    , d ( new JobPrivate( service ) ) {
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

bool Job::insecureFallback() const {
    return d->insecureFallback;
}

void Job::setInsecureFallback( bool insecureFallback ) {
    d->insecureFallback = insecureFallback;
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
    , d( new ReadPasswordJobPrivate( this ) )
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
    JobExecutor::instance()->enqueue( this );
}

WritePasswordJob::WritePasswordJob( const QString& service, QObject* parent )
    : Job( service, parent )
    , d( new WritePasswordJobPrivate( this ) ) {
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
    d->mode = WritePasswordJobPrivate::Binary;
}

void WritePasswordJob::setTextData( const QString& data ) {
    d->textData = data;
    d->mode = WritePasswordJobPrivate::Text;
}

void WritePasswordJob::doStart() {
    JobExecutor::instance()->enqueue( this );
}

DeletePasswordJob::DeletePasswordJob( const QString& service, QObject* parent )
    : Job( service, parent )
    , d( new DeletePasswordJobPrivate( this ) ) {
}

DeletePasswordJob::~DeletePasswordJob() {
    delete d;
}

void DeletePasswordJob::doStart() {
    //Internally, to delete a password we just execute a write job with no data set (null byte array).
    //In all current implementations, this deletes the entry so this is sufficient
    WritePasswordJob* job = new WritePasswordJob( service(), this );
    connect( job, SIGNAL(finished(QKeychain::Job*)), d, SLOT(jobFinished(QKeychain::Job*)) );
    job->setInsecureFallback(true);
    job->setSettings(settings());
    job->setKey( d->key );
    job->doStart();
}

QString DeletePasswordJob::key() const {
    return d->key;
}

void DeletePasswordJob::setKey( const QString& key ) {
    d->key = key;
}

void DeletePasswordJobPrivate::jobFinished( Job* job ) {
    q->setError( job->error() );
    q->setErrorString( job->errorString() );
    q->emitFinished();
}

JobExecutor::JobExecutor()
    : QObject( 0 )
    , m_runningJob( 0 )
{
}

void JobExecutor::enqueue( Job* job ) {
    m_queue.append( job );
    startNextIfNoneRunning();
}

void JobExecutor::startNextIfNoneRunning() {
    if ( m_queue.isEmpty() || m_runningJob )
        return;
    QPointer<Job> next;
    while ( !next && !m_queue.isEmpty() ) {
        next = m_queue.first();
        m_queue.pop_front();
    }
    if ( next ) {
        connect( next, SIGNAL(finished(QKeychain::Job*)), this, SLOT(jobFinished(QKeychain::Job*)) );
        connect( next, SIGNAL(destroyed(QObject*)), this, SLOT(jobDestroyed(QObject*)) );
        m_runningJob = next;
        if ( ReadPasswordJob* rpj = qobject_cast<ReadPasswordJob*>( m_runningJob ) )
            rpj->d->scheduledStart();
        else if ( WritePasswordJob* wpj = qobject_cast<WritePasswordJob*>( m_runningJob) )
            wpj->d->scheduledStart();
    }
}

void JobExecutor::jobDestroyed( QObject* object ) {
    Q_UNUSED( object ) // for release mode
    Q_ASSERT( object == m_runningJob );
    m_runningJob->disconnect( this );
    m_runningJob = 0;
    startNextIfNoneRunning();
}

void JobExecutor::jobFinished( Job* job ) {
    Q_UNUSED( job ) // for release mode
    Q_ASSERT( job == m_runningJob );
    m_runningJob->disconnect( this );
    m_runningJob = 0;
    startNextIfNoneRunning();
}

JobExecutor* JobExecutor::s_instance = 0;

JobExecutor* JobExecutor::instance() {
    if ( !s_instance )
        s_instance = new JobExecutor;
    return s_instance;
}
