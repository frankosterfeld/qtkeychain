/******************************************************************************
 *   Copyright (C) 2011-2014 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#ifndef KEYCHAIN_P_H
#define KEYCHAIN_P_H

#include <QCoreApplication>
#include <QObject>
#include <QPointer>
#include <QSettings>
#include <QVector>

#if defined(Q_OS_UNIX) && !defined(Q_OS_DARWIN)

#include <QDBusPendingCallWatcher>

#include "kwallet_interface.h"
#else

class QDBusPendingCallWatcher;

#endif

#include "keychain.h"

namespace QKeychain {

class JobExecutor;

class JobPrivate : public QObject {
    Q_OBJECT
public:
    JobPrivate( const QString& service_ )
        : error( NoError )
        , service( service_ )
        , autoDelete( true )
        , insecureFallback( false ) {}

    QKeychain::Error error;
    QString errorString;
    QString service;
    bool autoDelete;
    bool insecureFallback;
    QPointer<QSettings> settings;
};

class ReadPasswordJobPrivate : public QObject {
    Q_OBJECT
public:
    explicit ReadPasswordJobPrivate( ReadPasswordJob* qq ) : q( qq ), walletHandle( 0 ), dataType( Text ) {}
    void scheduledStart();

    ReadPasswordJob* const q;
    QByteArray data;
    QString key;
    int walletHandle;
    enum DataType {
        Binary,
        Text
    };
    DataType dataType;

#if defined(Q_OS_UNIX) && !defined(Q_OS_DARWIN)
    org::kde::KWallet* iface;
    static void gnomeKeyring_cb( int result, const char* string, ReadPasswordJobPrivate* data );
    friend class QKeychain::JobExecutor;
    void fallbackOnError(const QDBusError& err);

private Q_SLOTS:
    void kwalletWalletFound( QDBusPendingCallWatcher* watcher );
    void kwalletOpenFinished( QDBusPendingCallWatcher* watcher );
    void kwalletEntryTypeFinished( QDBusPendingCallWatcher* watcher );
    void kwalletReadFinished( QDBusPendingCallWatcher* watcher );
#else //moc's too dumb to respect above macros, so just define empty slot implementations
private Q_SLOTS:
    void kwalletWalletFound( QDBusPendingCallWatcher* ) {}
    void kwalletOpenFinished( QDBusPendingCallWatcher* ) {}
    void kwalletEntryTypeFinished( QDBusPendingCallWatcher* ) {}
    void kwalletReadFinished( QDBusPendingCallWatcher* ) {}
#endif

};

class WritePasswordJobPrivate : public QObject {
    Q_OBJECT
public:
    explicit WritePasswordJobPrivate( WritePasswordJob* qq ) : q( qq ), mode( Delete ) {}
    void scheduledStart();

    enum Mode {
        Delete,
        Text,
        Binary
    };

    static QString modeToString(Mode m);
    static Mode stringToMode(const QString& s);

    WritePasswordJob* const q;
    Mode mode;
    QString key;
    QByteArray binaryData;
    QString textData;

#if defined(Q_OS_UNIX) && !defined(Q_OS_DARWIN)
    org::kde::KWallet* iface;
    static void gnomeKeyring_cb( int result, WritePasswordJobPrivate* self );
    friend class QKeychain::JobExecutor;
    void fallbackOnError(const QDBusError& err);

private Q_SLOTS:
    void kwalletWalletFound( QDBusPendingCallWatcher* watcher );
    void kwalletOpenFinished( QDBusPendingCallWatcher* watcher );
    void kwalletWriteFinished( QDBusPendingCallWatcher* watcher );
#else
private Q_SLOTS:
    void kwalletWalletFound( QDBusPendingCallWatcher* ) {}
    void kwalletOpenFinished( QDBusPendingCallWatcher* ) {}
    void kwalletWriteFinished( QDBusPendingCallWatcher* ) {}
#endif
};

class DeletePasswordJobPrivate : public QObject {
    Q_OBJECT
public:
    explicit DeletePasswordJobPrivate( DeletePasswordJob* qq ) : q( qq ) {}
    void doStart();
    DeletePasswordJob* const q;
    QString key;
private Q_SLOTS:
    void jobFinished( QKeychain::Job* );
};

class JobExecutor : public QObject {
    Q_OBJECT
public:

    static JobExecutor* instance();

    void enqueue( Job* job );

private:
    explicit JobExecutor();
    void startNextIfNoneRunning();

private Q_SLOTS:
    void jobFinished( QKeychain::Job* );
    void jobDestroyed( QObject* object );

private:
    static JobExecutor* s_instance;
    Job* m_runningJob;
    QVector<QPointer<Job> > m_queue;
};

}

#endif // KEYCHAIN_P_H
