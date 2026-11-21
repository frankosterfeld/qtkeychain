#include <QtTest>

#include "qtkeychain/keychain.h"

namespace {
QByteArray generateRandomString(qsizetype size)
{
    std::vector<quint32> buffer(size, 0);
    QRandomGenerator::global()->fillRange(buffer.data(), size);
    return QByteArray(reinterpret_cast<char *>(buffer.data()),
                      static_cast<int>(size * sizeof(quint32)))
            .toBase64(QByteArray::Base64UrlEncoding)
            .mid(0, size);
}

} // namespace
class BasicTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void macOSKeychainPreference()
    {
        QKeychain::ReadPasswordJob job(QStringLiteral("QtKeychainTest"));
        job.setAutoDelete(false);
        QCOMPARE(job.macOSKeychainPreference(),
                 QKeychain::MacOSKeychainPreference::DataProtectionKeychainWithLegacyFallback);
        job.setMacOSKeychainPreference(QKeychain::MacOSKeychainPreference::LegacyKeychain);
        QCOMPARE(job.macOSKeychainPreference(), QKeychain::MacOSKeychainPreference::LegacyKeychain);
    }

    void test_data()
    {
        QTest::addColumn<QByteArray>("password");
        QTest::addColumn<QStringList>("usernames");

        QTest::newRow("normal password") << QByteArrayLiteral("this is a password") << QStringList{"", "user1", "user2"};
        QTest::newRow("1000") << generateRandomString(1000) << QStringList{"", "user1", "user2"};
        QTest::newRow("2000") << generateRandomString(2000)<< QStringList{"", "user1", "user2"};
        QTest::newRow("3000") << generateRandomString(3000)<< QStringList{"", "user1", "user2"};
        QTest::newRow("10000") << generateRandomString(10000)<< QStringList{"", "user1", "user2"};
        QTest::newRow("18944") << generateRandomString(18944)<< QStringList{"", "user1", "user2"};
    }

    void test()
    {
#ifdef Q_OS_MACOS
        QSKIP("This test case has no access to the keychain");
#endif
        const QStringList serviceKeys ={"", QStringLiteral("QtKeychainTest-%1").arg(QTest::currentDataTag())};
        QFETCH(QByteArray, password);
        QFETCH(QStringList, usernames);

        for (const auto& serviceKey: serviceKeys)
        {
            for (const auto& username : usernames)
            {
                QKeychain::WritePasswordJob writeJob(serviceKey);
                writeJob.setKey(username);
                writeJob.setBinaryData(username.toUtf8()+password);
                QSignalSpy writeSpy(&writeJob, &QKeychain::WritePasswordJob::finished);
                writeJob.start();
                writeSpy.wait();
#ifdef Q_OS_WIN
                QEXPECT_FAIL("18944", "Maximum for Windows is exceeded", Abort);
#endif
                qDebug() << "[write]" << writeJob.error() << ": " << writeJob.errorString();
                const auto expected = (serviceKey.isEmpty() && username.isEmpty()) ? QKeychain::EntryNotFound : QKeychain::NoError;
                QCOMPARE(writeJob.error(), expected);
            }
        }

        for (const auto& serviceKey: serviceKeys)
        {
            for (const auto& username : usernames)
            {
                QKeychain::ReadPasswordJob readJob(serviceKey);
                readJob.setKey(username);
                QSignalSpy readSpy(&readJob, &QKeychain::ReadPasswordJob::finished);
                readJob.start();
                readSpy.wait();
                qDebug() << "[read]" << readJob.error() << ": " << readJob.errorString();
                const auto expected = (serviceKey.isEmpty() && username.isEmpty()) ? QKeychain::EntryNotFound : QKeychain::NoError;
                QCOMPARE(readJob.error(), expected);
                if (expected == QKeychain::NoError) {
                    QCOMPARE(readJob.binaryData(), username.toUtf8()+password);
                }
            }
        }

        for (const auto& serviceKey: serviceKeys)
        {
            for (const auto& username : usernames)
            {
                QKeychain::DeletePasswordJob deleteJob(serviceKey);
                // Stack-allocated: do not let the job schedule its own deletion.
                // The read below runs a nested event loop and would deliver it.
                deleteJob.setAutoDelete(false);
                deleteJob.setKey(username);
                QSignalSpy deleteSpy(&deleteJob, &QKeychain::DeletePasswordJob::finished);
                deleteJob.start();
                deleteSpy.wait();
                qDebug() << "[delete]" << deleteJob.error() << ": " << deleteJob.errorString();
                const auto expected = (serviceKey.isEmpty() && username.isEmpty()) ? QKeychain::EntryNotFound : QKeychain::NoError;
                QCOMPARE(deleteJob.error(), expected);
                if (expected == QKeychain::NoError) {
                    QKeychain::ReadPasswordJob verifyJob(serviceKey);
                    verifyJob.setAutoDelete(false);
                    verifyJob.setKey(username);
                    QSignalSpy verifySpy(&verifyJob, &QKeychain::ReadPasswordJob::finished);
                    verifyJob.start();
                    verifySpy.wait();
                    QCOMPARE(verifyJob.error(), QKeychain::EntryNotFound);
                }
            }
        }
    }

    void textDataTest()
    {
#ifdef Q_OS_MACOS
        QSKIP("This test case has no access to the keychain");
#endif
        const QString serviceKey = QStringLiteral("QtKeychainTest-TextData");
        const QString username = QStringLiteral("testuser");

        // 1. Test setTextData() and textData() round-trip
        const QStringList testStrings = {
            QStringLiteral("simple_password"),
            QStringLiteral("p@ssw0rd!#$ 123"),
            QStringLiteral("contraseña"),
            QString::fromUtf8("пароль"),
            QString::fromUtf8("密码"),
            QString::fromUtf8("Hello 🌍")
        };

        for (const auto &text : testStrings) {
            QKeychain::WritePasswordJob writeJob(serviceKey);
            writeJob.setAutoDelete(false);
            writeJob.setKey(username);
            writeJob.setTextData(text);
            QSignalSpy writeSpy(&writeJob, &QKeychain::WritePasswordJob::finished);
            writeJob.start();
            writeSpy.wait();
            QCOMPARE(writeJob.error(), QKeychain::NoError);

            QKeychain::ReadPasswordJob readJob(serviceKey);
            readJob.setAutoDelete(false);
            readJob.setKey(username);
            QSignalSpy readSpy(&readJob, &QKeychain::ReadPasswordJob::finished);
            readJob.start();
            readSpy.wait();
            QCOMPARE(readJob.error(), QKeychain::NoError);
            QCOMPARE(readJob.textData(), text);

            QKeychain::DeletePasswordJob deleteJob(serviceKey);
            deleteJob.setAutoDelete(false);
            deleteJob.setKey(username);
            QSignalSpy deleteSpy(&deleteJob, &QKeychain::DeletePasswordJob::finished);
            deleteJob.start();
            deleteSpy.wait();
            QCOMPARE(deleteJob.error(), QKeychain::NoError);
        }

        // 2. Test reading UTF-16LE data (e.g. from cmdkey on Windows)
        // 't', 0, 'e', 0, 's', 0, 't', 0
        const QByteArray utf16leCmdkey = QByteArrayLiteral("t\x00e\x00s\x00t\x00");
        {
            QKeychain::WritePasswordJob writeJob(serviceKey);
            writeJob.setAutoDelete(false);
            writeJob.setKey(username);
            writeJob.setBinaryData(utf16leCmdkey);
            QSignalSpy writeSpy(&writeJob, &QKeychain::WritePasswordJob::finished);
            writeJob.start();
            writeSpy.wait();
            QCOMPARE(writeJob.error(), QKeychain::NoError);

            QKeychain::ReadPasswordJob readJob(serviceKey);
            readJob.setAutoDelete(false);
            readJob.setKey(username);
            QSignalSpy readSpy(&readJob, &QKeychain::ReadPasswordJob::finished);
            readJob.start();
            readSpy.wait();
            QCOMPARE(readJob.error(), QKeychain::NoError);
            QCOMPARE(readJob.textData(), QStringLiteral("test"));

            QKeychain::DeletePasswordJob deleteJob(serviceKey);
            deleteJob.setAutoDelete(false);
            deleteJob.setKey(username);
            QSignalSpy deleteSpy(&deleteJob, &QKeychain::DeletePasswordJob::finished);
            deleteJob.start();
            deleteSpy.wait();
            QCOMPARE(deleteJob.error(), QKeychain::NoError);
        }

        // 3. Test reading null-terminated UTF-16LE data
        const QByteArray utf16leNullTerminated = QByteArrayLiteral("t\x00e\x00s\x00t\x00\x00\x00");
        {
            QKeychain::WritePasswordJob writeJob(serviceKey);
            writeJob.setAutoDelete(false);
            writeJob.setKey(username);
            writeJob.setBinaryData(utf16leNullTerminated);
            QSignalSpy writeSpy(&writeJob, &QKeychain::WritePasswordJob::finished);
            writeJob.start();
            writeSpy.wait();
            QCOMPARE(writeJob.error(), QKeychain::NoError);

            QKeychain::ReadPasswordJob readJob(serviceKey);
            readJob.setAutoDelete(false);
            readJob.setKey(username);
            QSignalSpy readSpy(&readJob, &QKeychain::ReadPasswordJob::finished);
            readJob.start();
            readSpy.wait();
            QCOMPARE(readJob.error(), QKeychain::NoError);
            QCOMPARE(readJob.textData(), QStringLiteral("test"));

            QKeychain::DeletePasswordJob deleteJob(serviceKey);
            deleteJob.setAutoDelete(false);
            deleteJob.setKey(username);
            QSignalSpy deleteSpy(&deleteJob, &QKeychain::DeletePasswordJob::finished);
            deleteJob.start();
            deleteSpy.wait();
            QCOMPARE(deleteJob.error(), QKeychain::NoError);
        }

        // 4. Test reading legacy UTF-8 data
        const QByteArray utf8Legacy = QByteArrayLiteral("legacy_test");
        {
            QKeychain::WritePasswordJob writeJob(serviceKey);
            writeJob.setAutoDelete(false);
            writeJob.setKey(username);
            writeJob.setBinaryData(utf8Legacy);
            QSignalSpy writeSpy(&writeJob, &QKeychain::WritePasswordJob::finished);
            writeJob.start();
            writeSpy.wait();
            QCOMPARE(writeJob.error(), QKeychain::NoError);

            QKeychain::ReadPasswordJob readJob(serviceKey);
            readJob.setAutoDelete(false);
            readJob.setKey(username);
            QSignalSpy readSpy(&readJob, &QKeychain::ReadPasswordJob::finished);
            readJob.start();
            readSpy.wait();
            QCOMPARE(readJob.error(), QKeychain::NoError);
            QCOMPARE(readJob.textData(), QStringLiteral("legacy_test"));

            QKeychain::DeletePasswordJob deleteJob(serviceKey);
            deleteJob.setAutoDelete(false);
            deleteJob.setKey(username);
            QSignalSpy deleteSpy(&deleteJob, &QKeychain::DeletePasswordJob::finished);
            deleteJob.start();
            deleteSpy.wait();
            QCOMPARE(deleteJob.error(), QKeychain::NoError);
        }
    }
};

QTEST_MAIN(BasicTest)
#include "basic.moc"
