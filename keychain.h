/******************************************************************************
 *   Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include "qkeychain_export.h"

#include <QtCore/QString>

namespace QKeychain {
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
class QKEYCHAIN_EXPORT Keychain {
public:
    /**
     * Creates a Keychain object.
     *
     * @param service The service name of your service/application. Used as identifier,
     *        to disambiguate keys and avoid clashes with other applications.
     */
    explicit Keychain( const QString& service );

    /**
     * Destructor
     */
    ~Keychain();

    /**
     * Error codes
     */
    enum Error {
        NoError=0, /**< No error occurred, operation was successful */
        EntryNotFound, /**< For the given key no data was found */
        CouldNotDeleteEntry, /**< Could not delete existing secret data */
        AccessDeniedByUser, /**< User denied access to keychain */
        AccessDenied, /**< Access denied for other reasons */
        EntryAlreadyExists, /**< There is already an entry for the given key and overwriting was not enforced */
        NotImplemented, /**< Not implemented on platform */
        OtherError /**< Something else went wrong (errorString() might provide details) */
    };

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

}

#endif
