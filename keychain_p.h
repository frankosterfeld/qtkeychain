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
#include <QObject>
#include <QPointer>
#include <QSettings>

#if defined (Q_OS_UNIX) && (!defined(Q_WS_DARWIN))

#include <QDBusPendingCallWatcher>

#include "kwallet_interface.h"
#endif

#include "keychain.h"

namespace QKeychain {

class Job::Private : public QObject {
    Q_OBJECT
public:
    Private( const QString& service_ )
        : error( NoError )
        , service( service_ )
        , autoDelete( true ) {}

    QKeychain::Error error;
    QString errorString;
    QString service;
    bool autoDelete;
    QPointer<QSettings> settings;
};

class ReadPasswordJob::Private : public QObject {
    Q_OBJECT
public:
    explicit Private( ReadPasswordJob* qq ) : q( qq ), walletHandle( 0 ), dataType( Text ) {}
    void doStart();
    ReadPasswordJob* const q;
    QByteArray data;
    QString key;
    int walletHandle;
    enum DataType {
        Binary,
        Text
    };
    DataType dataType;

#if defined (Q_OS_UNIX) && (!defined(Q_WS_DARWIN))
    org::kde::KWallet* iface;

private Q_SLOTS:
    void kwalletOpenFinished( QDBusPendingCallWatcher* watcher );
    void kwalletEntryTypeFinished( QDBusPendingCallWatcher* watcher );
    void kwalletReadFinished( QDBusPendingCallWatcher* watcher );
#endif

};

class WritePasswordJob::Private : public QObject {
    Q_OBJECT
public:
    explicit Private( WritePasswordJob* qq ) : q( qq ), mode( Delete ) {}
    void doStart();
    enum Mode {
        Delete,
        Text,
        Binary
    };
    WritePasswordJob* const q;
    Mode mode;
    QString key;
    QByteArray binaryData;
    QString textData;

#if defined (Q_OS_UNIX) && (!defined(Q_WS_DARWIN))
    org::kde::KWallet* iface;

private Q_SLOTS:
    void kwalletOpenFinished( QDBusPendingCallWatcher* watcher );
    void kwalletWriteFinished( QDBusPendingCallWatcher* watcher );
#endif
};

class DeletePasswordJob::Private : public QObject {
    Q_OBJECT
public:
    explicit Private( DeletePasswordJob* qq ) : q( qq ) {}
    void doStart();
    DeletePasswordJob* const q;
    QString key;
private Q_SLOTS:
    void jobFinished( QKeychain::Job* );
};

}

#endif // KEYCHAIN_P_H
