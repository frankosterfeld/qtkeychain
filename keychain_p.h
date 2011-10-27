#ifndef KEYCHAIN_P_H
#define KEYCHAIN_P_H

#include "keychain.h"

class Keychain::Private {
public:
    explicit Private( const QString& s ) : service( s ) {}

    void writePasswordImpl( const QString& account, const QString& password );
    QString readPasswordImpl( const QString& account ) const;

    const QString service;
};

#endif // KEYCHAIN_P_H
