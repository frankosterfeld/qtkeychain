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

#if 0
/**
 * Provides access to platform-specific key stores for secure persistence of
 * passwords and other sensitive user data.
 *
 * On Windows, TODO
 * On Mac OS X, the OS X keychain is used.
 * On other Unixes, TODO
 *
 * TODO we don't guarantee anything
 */
class Keychain {
public:
    /**
     * Creates a Keychain object.
     *
     * @param service The service name of your service/application. Used as identifier,
     *        to disambiguate keys and avoid clashes with other applications.
     *        Must not be empty.
     * @param settings An optional settings object that is used to store the encrypted data
     *        if no keychain is available on the platform. Currently only used on Windows.
     *        If 0, a default-constructed QSettings object will be used.
     */
    explicit Keychain( const QString& service, QSettings* settings=0 );

    /**
     * Destructor
     */
    ~Keychain();

    /**
     * The service name used as identifier.
     */
    QString service() const;

    /**
     * The error code of the last operation.
     */
    Error error() const;

    /**
     * Human-readable error description of the last operation.
     */
    QString errorString() const;

    /**
     * Stores a @p password in the keychain, for a given @p key.
     * error() and errorString() hold the result of the write operation.
     *
     * @param key the key to store a password for
     * @param password the password to store
     * @param om Whether to overwrite existing passwords
     */
    void writePassword( const QString& key,
                        const QString& password );

    /**
     * Stores @p data in the keychain, for a given @p key.
     * error() and errorString() hold the result of the write operation.
     *
     * @param key the key to store a password for
     * @param data the data to store
     * @param om Whether to overwrite existing passwords
     */
    void writeEntry( const QString& key,
                     const QByteArray& data );

    /**
     * Reads the password for a given @p key from the keychain.
     * error() and errorString() hold the result of the read operation.
     *
     * @param key the key to read the password for
     */
    QString readPassword( const QString& key );

    /**
     * Reads data for a given @p key from the keychain.
     * error() and errorString() hold the result of the read operation.
     *
     * @param key the key to read the password for
     */
    QByteArray readEntry( const QString& key );

    /**
     * Returns whether the keychain has an entry with key @p key
     * error() and errorString() hold the result of the read operation.
     *
     * @param key the key to check for
     */
    bool entryExists( const QString& key );

    /**
     * Deletes the data for a @p key from the keychain.
     * error() and errorString() hold the result of the delete operation.
     *
     * @param key The key to delete the data for
     */
    void deleteEntry( const QString& key );

private:
    class Private;
    Private* const d;
    Q_DISABLE_COPY(Keychain)
};

class Keychain::Private {
    Q_DECLARE_TR_FUNCTIONS(Keychain::Private)
public:
    explicit Private( const QString& service_, QSettings* settings_ ) : service( service_ ), settings( settings_ ), error( NoError ) {}

    QKeychain::Error writeEntryImpl( const QString& account,
                                    const QByteArray& data,
                                    QString* errorString );
    QKeychain::Error deleteEntryImpl( const QString& account,
                                     QString* errorString );
    QKeychain::Error readEntryImpl( QByteArray* password,
                                   const QString& account,
                                   QString* errorString );
    QKeychain::Error entryExistsImpl( bool* exists,
                                     const QString& key,
                                     QString* errorString );
    const QString service;
    QPointer<QSettings> settings;
    QKeychain::Error error;
    QString errorString;
};


#endif

}

#endif // KEYCHAIN_P_H
