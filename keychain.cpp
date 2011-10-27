#include "keychain.h"
#include "keychain_p.h"

KeychainException::KeychainException( const QString& message )
    : std::runtime_error( message.toStdString() )
    , m_message( message )
{}

KeychainException::~KeychainException() throw() {
}

QString KeychainException::message() const {
    return m_message;
}

Keychain::Keychain( const QString& service )
    : d( new Private( service ) )
{
}

QString Keychain::service() const
{
    return d->service;
}

void Keychain::writePassword( const QString& account, const QString& password )
{
    d->writePasswordImpl( account, password );
}

QString Keychain::readPassword( const QString& account ) const
{
    return d->readPasswordImpl( account );
}
