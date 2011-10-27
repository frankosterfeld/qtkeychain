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

class Keychain {
public:
    explicit Keychain( const QString& service );
    ~Keychain();

    enum Error {
        NoError=0,
        PasswordNotFound,
        CouldNotDeleteExistingPassword,
        AccessDenied,
        EntryAlreadyExists,
        OtherError
    };

    enum OverwriteMode {
        DoNotOverwrite,
        ForceOverwrite
    };

    QString service() const;
    Error error() const;
    QString errorString() const;

    void writePassword( const QString& account,
                        const QString& password,
                        OverwriteMode om=DoNotOverwrite );
    QString readPassword( const QString& account );
    void deletePassword( const QString& account );

private:
    class Private;
    Private* const d;
    Q_DISABLE_COPY(Keychain)
};

#endif
