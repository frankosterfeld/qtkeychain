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
    explicit Private( ReadPasswordJob* qq ) : q( qq ) {}
    void doStart();
    ReadPasswordJob* const q;
    QByteArray data;
    QString key;
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
};

}

#endif // KEYCHAIN_P_H
