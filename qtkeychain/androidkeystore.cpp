#include "androidkeystore_p.h"

#if QT_VERSION < QT_VERSION_CHECK(5, 7, 0)
#  include "private/qjni_p.h"
#endif

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#  include <QAndroidJniEnvironment>
#endif

using namespace QKeychain;

using namespace android::content;
using namespace android::security;

using namespace java::io;
using namespace java::lang;
using namespace java::math;
using namespace java::util;
using namespace java::security;
using namespace java::security::spec;

using namespace javax::crypto;
using namespace javax::security::auth::x500;
using namespace javax::security::cert;

const BigInteger BigInteger::ONE =
        BigInteger::getStaticObjectField("java/math/BigInteger", "ONE", "Ljava/math/BigInteger;");

const int Calendar::YEAR = Calendar::getStaticField<jint>("java/util/Calendar", "YEAR");

const int Cipher::DECRYPT_MODE =
        Cipher::getStaticField<jint>("javax/crypto/Cipher", "DECRYPT_MODE");
const int Cipher::ENCRYPT_MODE =
        Cipher::getStaticField<jint>("javax/crypto/Cipher", "ENCRYPT_MODE");

namespace {

#if QT_VERSION < QT_VERSION_CHECK(5, 7, 0)

struct JNIObject
{
    JNIObject(QSharedPointer<QJNIObjectPrivate> d) : d(d) { }

    static JNIObject fromLocalRef(jobject o)
    {
        return JNIObject(
                QSharedPointer<QJNIObjectPrivate>::create(QJNIObjectPrivate::fromLocalRef(o)));
    }

    jobject object() const { return d->object(); }
    QSharedPointer<QJNIObjectPrivate> d;
};

#else

using JNIObject = QAndroidJniObject;

#endif

QByteArray fromArray(const jbyteArray array)
{
    QAndroidJniEnvironment env;
    jbyte *const bytes = env->GetByteArrayElements(array, nullptr);
    const QByteArray result(reinterpret_cast<const char *>(bytes), env->GetArrayLength(array));
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

JNIObject toArray(const QByteArray &bytes)
{
    QAndroidJniEnvironment env;
    const int length = bytes.length();
    JNIObject array = JNIObject::fromLocalRef(env->NewByteArray(length));
    env->SetByteArrayRegion(static_cast<jbyteArray>(array.object()), 0, length,
                            reinterpret_cast<const jbyte *>(bytes.constData()));
    return array;
}

} // namespace

bool Object::handleExceptions()
{
    QAndroidJniEnvironment env;

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    return true;
}

KeyPairGenerator KeyPairGenerator::getInstance(const QString &algorithm, const QString &provider)
{
    return handleExceptions(callStaticObjectMethod(
            "java/security/KeyPairGenerator", "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
            fromString(algorithm).object(), fromString(provider).object()));
}

KeyPair KeyPairGenerator::generateKeyPair() const
{
    return handleExceptions(callObjectMethod("generateKeyPair", "()Ljava/security/KeyPair;"));
}

bool KeyPairGenerator::initialize(const AlgorithmParameterSpec &spec) const
{
    callMethod<void>("initialize", "(Ljava/security/spec/AlgorithmParameterSpec;)V", spec.object());
    return handleExceptions();
}

bool KeyStore::containsAlias(const QString &alias) const
{
    return handleExceptions(callMethod<jboolean>("containsAlias", "(Ljava/lang/String;)Z",
                                                 fromString(alias).object()));
}

bool KeyStore::deleteEntry(const QString &alias) const
{
    callMethod<void>("deleteEntry", "(Ljava/lang/String;)V", fromString(alias).object());
    return handleExceptions();
}

KeyStore KeyStore::getInstance(const QString &type)
{
    return handleExceptions(callStaticObjectMethod("java/security/KeyStore", "getInstance",
                                                   "(Ljava/lang/String;)Ljava/security/KeyStore;",
                                                   fromString(type).object()));
}

KeyStore::Entry KeyStore::getEntry(const QString &alias,
                                   const KeyStore::ProtectionParameter &param) const
{
    return handleExceptions(
            callObjectMethod("getEntry",
                             "(Ljava/lang/String;Ljava/security/"
                             "KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;",
                             fromString(alias).object(), param.object()));
}

bool KeyStore::load(const KeyStore::LoadStoreParameter &param) const
{
    callMethod<void>("load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", param.object());
    return handleExceptions();
}

Calendar Calendar::getInstance()
{
    return handleExceptions(
            callStaticObjectMethod("java/util/Calendar", "getInstance", "()Ljava/util/Calendar;"));
}

bool Calendar::add(int field, int amount) const
{
    callMethod<void>("add", "(II)V", field, amount);
    return handleExceptions();
}

Date Calendar::getTime() const
{
    return handleExceptions(callObjectMethod("getTime", "()Ljava/util/Date;"));
}

KeyPairGeneratorSpec::Builder::Builder(const Context &context)
    : Object(QAndroidJniObject("android/security/KeyPairGeneratorSpec$Builder",
                               "(Landroid/content/Context;)V", context.object()))
{
    handleExceptions();
}

KeyPairGeneratorSpec::Builder KeyPairGeneratorSpec::Builder::setAlias(const QString &alias) const
{
    return handleExceptions(callObjectMethod(
            "setAlias", "(Ljava/lang/String;)Landroid/security/KeyPairGeneratorSpec$Builder;",
            fromString(alias).object()));
}

KeyPairGeneratorSpec::Builder
KeyPairGeneratorSpec::Builder::setSubject(const X500Principal &subject) const
{
    return handleExceptions(callObjectMethod("setSubject",
                                             "(Ljavax/security/auth/x500/X500Principal;)Landroid/"
                                             "security/KeyPairGeneratorSpec$Builder;",
                                             subject.object()));
}

KeyPairGeneratorSpec::Builder
KeyPairGeneratorSpec::Builder::setSerialNumber(const BigInteger &serial) const
{
    return handleExceptions(callObjectMethod(
            "setSerialNumber",
            "(Ljava/math/BigInteger;)Landroid/security/KeyPairGeneratorSpec$Builder;",
            serial.object()));
}

KeyPairGeneratorSpec::Builder KeyPairGeneratorSpec::Builder::setStartDate(const Date &date) const
{
    return handleExceptions(callObjectMethod(
            "setStartDate", "(Ljava/util/Date;)Landroid/security/KeyPairGeneratorSpec$Builder;",
            date.object()));
}

KeyPairGeneratorSpec::Builder KeyPairGeneratorSpec::Builder::setEndDate(const Date &date) const
{
    return handleExceptions(callObjectMethod(
            "setEndDate", "(Ljava/util/Date;)Landroid/security/KeyPairGeneratorSpec$Builder;",
            date.object()));
}

KeyPairGeneratorSpec KeyPairGeneratorSpec::Builder::build() const
{
    return handleExceptions(callObjectMethod("build", "()Landroid/security/KeyPairGeneratorSpec;"));
}

X500Principal::X500Principal(const QString &name)
    : Object(QAndroidJniObject("javax/security/auth/x500/X500Principal", "(Ljava/lang/String;)V",
                               fromString(name).object()))
{
    handleExceptions();
}

Certificate KeyStore::PrivateKeyEntry::getCertificate() const
{
    return handleExceptions(
            callObjectMethod("getCertificate", "()Ljava/security/cert/Certificate;"));
}

PrivateKey KeyStore::PrivateKeyEntry::getPrivateKey() const
{
    return handleExceptions(callObjectMethod("getPrivateKey", "()Ljava/security/PrivateKey;"));
}

PublicKey Certificate::getPublicKey() const
{
    return handleExceptions(callObjectMethod("getPublicKey", "()Ljava/security/PublicKey;"));
}

ByteArrayInputStream::ByteArrayInputStream(const QByteArray &bytes)
    : InputStream(
              QAndroidJniObject("java/io/ByteArrayInputStream", "([B)V", toArray(bytes).object()))
{
}

ByteArrayOutputStream::ByteArrayOutputStream()
    : OutputStream(QAndroidJniObject("java/io/ByteArrayOutputStream"))
{
    handleExceptions();
}

QByteArray ByteArrayOutputStream::toByteArray() const
{
    const QAndroidJniObject wrapper = callObjectMethod<jbyteArray>("toByteArray");

    if (!handleExceptions())
        return QByteArray();

    return fromArray(static_cast<jbyteArray>(wrapper.object()));
}

int InputStream::read() const
{
    return handleExceptions(callMethod<int>("read"), -1);
}

bool OutputStream::write(const QByteArray &bytes) const
{
    callMethod<void>("write", "([B)V", toArray(bytes).object());
    return handleExceptions();
}

bool OutputStream::close() const
{
    callMethod<void>("close");
    return handleExceptions();
}

bool OutputStream::flush() const
{
    callMethod<void>("flush");
    return handleExceptions();
}

Cipher Cipher::getInstance(const QString &transformation)
{
    return handleExceptions(callStaticObjectMethod("javax/crypto/Cipher", "getInstance",
                                                   "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                                                   fromString(transformation).object()));
}

bool Cipher::init(int opMode, const Key &key) const
{
    callMethod<void>("init", "(ILjava/security/Key;)V", opMode, key.object());
    return handleExceptions();
}

CipherOutputStream::CipherOutputStream(const OutputStream &stream, const Cipher &cipher)
    : FilterOutputStream(QAndroidJniObject("javax/crypto/CipherOutputStream",
                                           "(Ljava/io/OutputStream;Ljavax/crypto/Cipher;)V",
                                           stream.object(), cipher.object()))
{
    handleExceptions();
}

CipherInputStream::CipherInputStream(const InputStream &stream, const Cipher &cipher)
    : FilterInputStream(QAndroidJniObject("javax/crypto/CipherInputStream",
                                          "(Ljava/io/InputStream;Ljavax/crypto/Cipher;)V",
                                          stream.object(), cipher.object()))
{
    handleExceptions();
}
