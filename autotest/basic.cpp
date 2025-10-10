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
        const QString serviceKey = QStringLiteral("QtKeychainTest-%1").arg(QTest::currentDataTag());
        QFETCH(QByteArray, password);
        QFETCH(QStringList, usernames);

        for (const auto& username : usernames)
        {
            QKeychain::WritePasswordJob writeJob(serviceKey);
            writeJob.setKey(username);
            writeJob.setBinaryData(password);
            QSignalSpy writeSpy(&writeJob, &QKeychain::WritePasswordJob::finished);
            writeJob.start();
            writeSpy.wait();
#ifdef Q_OS_WIN
            QEXPECT_FAIL("18944", "Maximum for Windows is exceeded", Abort);
#endif
            qDebug() << writeJob.errorString();
            QCOMPARE(writeJob.error(), QKeychain::NoError);
        }

        for (const auto& username : usernames)
        {
            QKeychain::ReadPasswordJob readJob(serviceKey);
            readJob.setKey(username);
            QSignalSpy readSpy(&readJob, &QKeychain::ReadPasswordJob::finished);
            readJob.start();
            readSpy.wait();
            QCOMPARE(readJob.error(), QKeychain::NoError);
            QCOMPARE(readJob.binaryData(), password);
        }

        for (const auto& username : usernames)
        {
            QKeychain::DeletePasswordJob deleteJob(serviceKey);
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
