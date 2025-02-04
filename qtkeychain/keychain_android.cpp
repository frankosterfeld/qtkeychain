/******************************************************************************
 *   Copyright (C) 2016 Mathias Hasselmann <mathias.hasselmann@kdab.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include "keychain_p.h"

#include "androidkeystore_p.h"
#include "plaintextstore_p.h"

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#  include <QtAndroid>
#endif

using namespace QKeychain;

using android::content::Context;
using android::security::KeyPairGeneratorSpec;

using java::io::ByteArrayInputStream;
using java::io::ByteArrayOutputStream;
using java::security::KeyPair;
using java::security::KeyPairGenerator;
using java::security::KeyStore;
using java::security::interfaces::RSAPrivateKey;
using java::security::interfaces::RSAPublicKey;
using java::util::Calendar;

using javax::crypto::Cipher;
using javax::crypto::CipherInputStream;
using javax::crypto::CipherOutputStream;
using javax::security::auth::x500::X500Principal;

namespace {

inline QString makeAlias(const QString &service, const QString &key)
{
    return service + QLatin1Char('/') + key;
}

} // namespace

void ReadPasswordJobPrivate::scheduledStart()
{
    PlainTextStore plainTextStore(q->service(), q->settings());

    if (!plainTextStore.contains(q->key())) {
        q->emitFinishedWithError(Error::EntryNotFound, tr("Entry not found"));
        return;
    }

    const QByteArray &encryptedData = plainTextStore.readData(q->key());
    const auto keyStore = KeyStore::getInstance(QStringLiteral("AndroidKeyStore"));

    if (!keyStore || !keyStore.load()) {
        q->emitFinishedWithError(Error::AccessDenied, tr("Could not open keystore"));
        return;
    }

    const auto &alias = makeAlias(q->service(), q->key());
    const KeyStore::PrivateKeyEntry entry = keyStore.getEntry(alias);

    if (!entry) {
        q->emitFinishedWithError(Error::AccessDenied,
                                 tr("Could not retrieve private key from keystore"));
        return;
    }

    const auto cipher = Cipher::getInstance(QStringLiteral("RSA/ECB/PKCS1Padding"));

    if (!cipher || !cipher.init(Cipher::DECRYPT_MODE, entry.getPrivateKey())) {
        q->emitFinishedWithError(Error::OtherError, tr("Could not create decryption cipher"));
        return;
    }

    QByteArray plainData;
    const CipherInputStream inputStream(ByteArrayInputStream(encryptedData), cipher);

    for (int nextByte; (nextByte = inputStream.read()) != -1;)
        plainData.append(nextByte);

    mode = plainTextStore.readMode(q->key());
    data = plainData;
    q->emitFinished();
}

void WritePasswordJobPrivate::scheduledStart()
{
    const KeyStore keyStore = KeyStore::getInstance(QStringLiteral("AndroidKeyStore"));

    if (!keyStore || !keyStore.load()) {
        q->emitFinishedWithError(Error::AccessDenied, tr("Could not open keystore"));
        return;
    }

    const auto &alias = makeAlias(q->service(), q->key());
    if (!keyStore.containsAlias(alias)) {
        const auto start = Calendar::getInstance();
        const auto end = Calendar::getInstance();
        end.add(Calendar::YEAR, 99);

        const KeyPairGeneratorSpec spec =
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
                KeyPairGeneratorSpec::Builder(Context(QtAndroid::androidActivity()))
                        .
#elif QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
                KeyPairGeneratorSpec::Builder(
                        Context(QNativeInterface::QAndroidApplication::context()))
                        .
#elif QT_VERSION < QT_VERSION_CHECK(6, 7, 0)
                KeyPairGeneratorSpec::Builder(
                        Context((jobject)QNativeInterface::QAndroidApplication::context()))
                        .
#else
                KeyPairGeneratorSpec::Builder(
                        Context(QNativeInterface::QAndroidApplication::context().object<jobject>()))
                        .
#endif
                setAlias(alias)
                        .setSubject(
                                X500Principal(QStringLiteral("CN=QtKeychain, O=Android Authority")))
                        .setSerialNumber(java::math::BigInteger::ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();

        const auto generator = KeyPairGenerator::getInstance(QStringLiteral("RSA"),
                                                             QStringLiteral("AndroidKeyStore"));

        if (!generator) {
            q->emitFinishedWithError(Error::OtherError,
                                     tr("Could not create private key generator"));
            return;
        }

        generator.initialize(spec);

        if (!generator.generateKeyPair()) {
            q->emitFinishedWithError(Error::OtherError, tr("Could not generate new private key"));
            return;
        }
    }

    const KeyStore::PrivateKeyEntry entry = keyStore.getEntry(alias);

    if (!entry) {
        q->emitFinishedWithError(Error::AccessDenied,
                                 tr("Could not retrieve private key from keystore"));
        return;
    }

    const RSAPublicKey publicKey = entry.getCertificate().getPublicKey();
    const auto cipher = Cipher::getInstance(QStringLiteral("RSA/ECB/PKCS1Padding"));

    if (!cipher || !cipher.init(Cipher::ENCRYPT_MODE, publicKey)) {
        q->emitFinishedWithError(Error::OtherError, tr("Could not create encryption cipher"));
        return;
    }

    ByteArrayOutputStream outputStream;
    CipherOutputStream cipherOutputStream(outputStream, cipher);

    if (!cipherOutputStream.write(data) || !cipherOutputStream.close()) {
        q->emitFinishedWithError(Error::OtherError, tr("Could not encrypt data"));
        return;
    }

    PlainTextStore plainTextStore(q->service(), q->settings());
    plainTextStore.write(q->key(), outputStream.toByteArray(), mode);

    if (plainTextStore.error() != NoError)
        q->emitFinishedWithError(plainTextStore.error(), plainTextStore.errorString());
    else
        q->emitFinished();
}

void DeletePasswordJobPrivate::scheduledStart()
{
    const auto keyStore = KeyStore::getInstance(QStringLiteral("AndroidKeyStore"));

    if (!keyStore || !keyStore.load()) {
        q->emitFinishedWithError(Error::AccessDenied, tr("Could not open keystore"));
        return;
    }

    const auto &alias = makeAlias(q->service(), q->key());
    if (!keyStore.deleteEntry(alias)) {
        q->emitFinishedWithError(Error::OtherError,
                                 tr("Could not remove private key from keystore"));
        return;
    }

    PlainTextStore plainTextStore(q->service(), q->settings());
    plainTextStore.remove(q->key());

    if (plainTextStore.error() != NoError)
        q->emitFinishedWithError(plainTextStore.error(), plainTextStore.errorString());
    else
        q->emitFinished();
}

bool QKeychain::isAvailable()
{
    return true;
}
