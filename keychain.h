#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include <QString>

#include <stdexcept>

class KeychainException : public std::runtime_error {
public:
    explicit KeychainException( const QString& message );
    ~KeychainException() throw();
    QString message() const;

private:
    QString m_message;
};

class Keychain {
public:
    explicit Keychain( const QString& service );
    ~Keychain();

    QString service() const;

    void writePassword( const QString& account, const QString& password );
    QString readPassword( const QString& account ) const;

private:
    class Private;
    Private* const d;
    Q_DISABLE_COPY(Keychain)
};

#endif

