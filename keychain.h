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

#include <QtCore/QString>

/**
 *
 */
class Keychain {
public:
    /**
     * Creates a Keychain object.
     *
     * @param service The service name of your service/application. Used as identifier,
     *        to disambiguate and avoid clashes with other applications.
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
        NoError=0, /*< No error occurred, operation was successful */
        PasswordNotFound, /*< For the given account no password was found */
        CouldNotDeletePassword, /*< Could not delete existing password */
        AccessDeniedByUser, /*< User denied access to keychain */
        AccessDenied, /*< Access denied for other reasons */
        EntryAlreadyExists, /*< There is already a password for the given account and overwriting was not enforced */
        OtherError /*< Something else went wrong (errorString() might provide details) */
    };

    /**
     * Overwrite mode when writing passwords to the keychain
     */
    enum OverwriteMode {
        DoNotOverwrite, /*< Do not overwrite existing entries */
        ForceOverwrite  /*< Replace old passowrd by new one */
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
     * Stores a @p password in the keychain, for a given @p account.
     * error() and errorString() hold the result of the write operation.
     *
     * @param account the account to store a password for
     * @param the password to store
     * @param om Whether to overwrite existing passwords
     */
    void writePassword( const QString& account,
                        const QString& password,
                        OverwriteMode om=DoNotOverwrite );

    /**
     * Reads the @p password for an @p account from the keychain.
     * error() and errorString() hold the result of the read operation.
     *
     * @param account the account ot read the password for
     */
    QString readPassword( const QString& account );

    /**
     * Deletes the @p password for an @p account from the keychain.
     * error() and errorString() hold the result of the read operation.
     *
     * @param account The account to delete the password for
     */
    void deletePassword( const QString& account );

private:
    class Private;
    Private* const d;
    Q_DISABLE_COPY(Keychain)
};

#endif
