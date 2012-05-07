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

void ReadPasswordJob::Private::doStart() {
    q->emitFinishedWithError( NotImplemented, QString() );
}

void WritePasswordJob::Private::doStart() {
    iface = new org::kde::KWallet( QLatin1String("org.kde.kwalletd"), QLatin1String("/modules/kwalletd"), QDBusConnection::sessionBus(), this );
    const QDBusPendingReply<int> reply = iface->open( QLatin1String("kdewallet"), 0, q->service() );
    QDBusPendingCallWatcher* watcher = new QDBusPendingCallWatcher( reply, this );
    connect( watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(kwalletOpenFinished(QDBusPendingCallWatcher*)) );
    //q->emitFinishedWithError( NotImplemented, QString() );
}

void WritePasswordJob::Private::kwalletOpenFinished( QDBusPendingCallWatcher* watcher ) {
    watcher->deleteLater();
    QDBusPendingReply<int> reply = *watcher;
    if ( reply.isError() ) {
        const QDBusError err = reply.error();
        q->emitFinishedWithError( OtherError, tr("Could not open wallet: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );
        return;
    }

    const int handle = reply.value();

    QDBusPendingReply<int> nextReply;

    if ( !textData.isEmpty() )
        nextReply = iface->writePassword( handle, q->service(), key, textData, q->service() );
    else if ( !binaryData.isEmpty() )
        nextReply = iface->writeEntry( handle, q->service(), key, binaryData, q->service() );
    else
        nextReply = iface->removeEntry( handle, q->service(), key, q->service() );

    QDBusPendingCallWatcher* nextWatcher = new QDBusPendingCallWatcher( nextReply, this );
    connect( nextWatcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(kwalletWriteFinished(QDBusPendingCallWatcher*)) );
}

void WritePasswordJob::Private::kwalletWriteFinished( QDBusPendingCallWatcher* watcher ) {
    watcher->deleteLater();
    QDBusPendingReply<int> reply = *watcher;
    if ( reply.isError() ) {
        const QDBusError err = reply.error();
        q->emitFinishedWithError( OtherError, tr("Could not open wallet: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );
        return;
    }

    q->emitFinished();
}
