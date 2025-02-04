/******************************************************************************
 *   Copyright (C) 2016 Mathias Hasselmann <mathias.hasselmann@kdab.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#ifndef QTKEYCHAIN_ANDROIDKEYSTORE_P_H
#define QTKEYCHAIN_ANDROIDKEYSTORE_P_H

#include <QtGlobal>

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#  include <QAndroidJniObject>
#else
#  include <QJniObject>
#  include <QJniEnvironment>

typedef QJniObject QAndroidJniObject;
typedef QJniEnvironment QAndroidJniEnvironment;

#endif

namespace QKeychain {

namespace javax {
namespace security {

namespace auth {
namespace x500 {
class X500Principal;
}
} // namespace auth
namespace cert {
class Certificate;
}

} // namespace security
} // namespace javax

namespace java {
namespace lang {

class Object : protected QAndroidJniObject
{
public:
    inline Object(jobject object) : QAndroidJniObject(object) { }
    inline Object(const QAndroidJniObject &object) : QAndroidJniObject(object) { }
    inline operator bool() const { return isValid(); }

    using QAndroidJniObject::object;
    using QAndroidJniObject::toString;

protected:
    static bool handleExceptions();

    template <typename T>
    static T handleExceptions(const T &result, const T &resultOnError = T());
};

template <typename T>
inline T Object::handleExceptions(const T &result, const T &resultOnError)
{
    if (!handleExceptions())
        return resultOnError;

    return result;
}

} // namespace lang

namespace io {

class InputStream : public java::lang::Object
{
public:
    using Object::Object;

    int read() const;
};

class ByteArrayInputStream : public InputStream
{
public:
    using InputStream::InputStream;

    explicit ByteArrayInputStream(const QByteArray &bytes);
};

class FilterInputStream : public InputStream
{
public:
    using InputStream::InputStream;
};

class OutputStream : public java::lang::Object
{
public:
    using Object::Object;

    bool write(const QByteArray &bytes) const;
    bool flush() const;
    bool close() const;
};

class ByteArrayOutputStream : public OutputStream
{
public:
    using OutputStream::OutputStream;

    ByteArrayOutputStream();

    QByteArray toByteArray() const;
};

class FilterOutputStream : public OutputStream
{
public:
    using OutputStream::OutputStream;
};

} // namespace io

namespace math {

class BigInteger : public java::lang::Object
{
public:
    using Object::Object;

    static const BigInteger ZERO;
    static const BigInteger ONE;
    static const BigInteger TEN;
};

} // namespace math

namespace util {

class Date : public java::lang::Object
{
public:
    using Object::Object;
};

class Calendar : public java::lang::Object
{
public:
    using Object::Object;

    static const int YEAR;
    static const int MONTH;
    static const int DAY;
    static const int HOUR;
    static const int MINUTE;
    static const int SECOND;
    static const int MILLISECOND;

    static Calendar getInstance();

    bool add(int field, int amount) const;
    Date getTime() const;
};

} // namespace util

namespace security {
namespace spec {

class AlgorithmParameterSpec : public java::lang::Object
{
public:
    using Object::Object;
};

} // namespace spec

class Key : public java::lang::Object
{
public:
    using Object::Object;
};

class PrivateKey : public Key
{
public:
    using Key::Key;

    PrivateKey(const Key &init) : Key(init) { }
};

class PublicKey : public Key
{
public:
    using Key::Key;

    PublicKey(const Key &init) : Key(init) { }
};

class KeyPair : public java::lang::Object
{
public:
    using Object::Object;
};

class KeyPairGenerator : public java::lang::Object
{
public:
    using Object::Object;

    static KeyPairGenerator getInstance(const QString &algorithm, const QString &provider);
    KeyPair generateKeyPair() const;
    bool initialize(const spec::AlgorithmParameterSpec &spec) const;
};

class KeyStore : public java::lang::Object
{
public:
    class Entry : public java::lang::Object
    {
    public:
        using Object::Object;
    };

    class PrivateKeyEntry : public Entry
    {
    public:
        using Entry::Entry;

        inline PrivateKeyEntry(const Entry &init) : Entry(init) { }

        javax::security::cert::Certificate getCertificate() const;
        java::security::PrivateKey getPrivateKey() const;
    };

    class LoadStoreParameter : public java::lang::Object
    {
    public:
        using Object::Object;
    };

    class ProtectionParameter : public java::lang::Object
    {
    public:
        using Object::Object;
    };

    using Object::Object;

    bool containsAlias(const QString &alias) const;
    bool deleteEntry(const QString &alias) const;
    static KeyStore getInstance(const QString &type);
    Entry getEntry(const QString &alias, const ProtectionParameter &param = nullptr) const;
    bool load(const LoadStoreParameter &param = nullptr) const;
};

namespace interfaces {

class RSAPrivateKey : public PrivateKey
{
public:
    using PrivateKey::PrivateKey;

    RSAPrivateKey(const PrivateKey &init) : PrivateKey(init) { }
};

class RSAPublicKey : public PublicKey
{
public:
    using PublicKey::PublicKey;

    RSAPublicKey(const PublicKey &init) : PublicKey(init) { }
};

} // namespace interfaces

} // namespace security
} // namespace java

namespace android {
namespace content {

class Context : public java::lang::Object
{
public:
    using Object::Object;
};

} // namespace content

namespace security {

class KeyPairGeneratorSpec : public java::security::spec::AlgorithmParameterSpec
{
public:
    class Builder : public java::lang::Object
    {
    public:
        using Object::Object;

        explicit Builder(const android::content::Context &context);

        Builder setAlias(const QString &alias) const;
        Builder setSubject(const javax::security::auth::x500::X500Principal &subject) const;
        Builder setSerialNumber(const java::math::BigInteger &serial) const;
        Builder setStartDate(const java::util::Date &date) const;
        Builder setEndDate(const java::util::Date &date) const;
        KeyPairGeneratorSpec build() const;
    };

    using AlgorithmParameterSpec::AlgorithmParameterSpec;
};

} // namespace security
} // namespace android

namespace javax {
namespace crypto {

class Cipher : public java::lang::Object
{
public:
    static const int DECRYPT_MODE;
    static const int ENCRYPT_MODE;

    using Object::Object;

    static Cipher getInstance(const QString &transformation);
    bool init(int opMode, const java::security::Key &key) const;
};

class CipherInputStream : public java::io::FilterInputStream
{
public:
    using FilterInputStream::FilterInputStream;

    explicit CipherInputStream(const InputStream &stream, const Cipher &cipher);
};

class CipherOutputStream : public java::io::FilterOutputStream
{
public:
    using FilterOutputStream::FilterOutputStream;

    explicit CipherOutputStream(const OutputStream &stream, const Cipher &cipher);
};

} // namespace crypto

namespace security {
namespace auth {
namespace x500 {

class X500Principal;

class X500Principal : public java::lang::Object
{
public:
    using Object::Object;

    explicit X500Principal(const QString &name);
};

} // namespace x500
} // namespace auth

namespace cert {

class Certificate : public java::lang::Object
{
public:
    using Object::Object;

    java::security::PublicKey getPublicKey() const;
};

} // namespace cert

} // namespace security
} // namespace javax

} // namespace QKeychain

#endif // QTKEYCHAIN_ANDROIDKEYSTORE_P_H
