#include "keychain_p.h"

QString Keychain::Private::readPasswordImpl( const QString& account ) const {
    throw KeychainException( QLatin1String("not implemented") );
}

void Keychain::Private::writePasswordImpl( const QString& account, const QString& password ) {
    throw KeychainException( QLatin1String("not implemented") );
}

