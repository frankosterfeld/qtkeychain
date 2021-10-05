#include <QDebug>

#include "keychainclass.h"

KeyChainClass::KeyChainClass(QObject* parent) :
    QObject(parent),
    m_readCredentialJob(QLatin1String("keychain.example.project.app")),
    m_writeCredentialJob(QLatin1String("keychain.example.project.app")),
    m_deleteCredentialJob(QLatin1String("keychain.example.project.app"))
{
    m_readCredentialJob.setAutoDelete(false);
    m_writeCredentialJob.setAutoDelete(false);
    m_deleteCredentialJob.setAutoDelete(false);
}

void KeyChainClass::readKey(const QString &key)
{
    m_readCredentialJob.setKey(key);

    QObject::connect(&m_readCredentialJob, &QKeychain::ReadPasswordJob::finished, [=](){
        if (m_readCredentialJob.error()) {
            emit error(tr("Read key failed: %1").arg(qPrintable(m_readCredentialJob.errorString())));
            return;
        }
        emit keyRestored(key, m_readCredentialJob.textData());
    });

    m_readCredentialJob.start();
}

void KeyChainClass::writeKey(const QString &key, const QString &value)
{
    m_writeCredentialJob.setKey(key);

    QObject::connect(&m_writeCredentialJob, &QKeychain::WritePasswordJob::finished, [=](){
        if (m_writeCredentialJob.error()) {
            emit error(tr("Write key failed: %1").arg(qPrintable(m_writeCredentialJob.errorString())));
            return;
        }

        emit keyStored(key);
    });

    m_writeCredentialJob.setTextData(value);
    m_writeCredentialJob.start();
}

void KeyChainClass::deleteKey(const QString &key)
{
    m_deleteCredentialJob.setKey(key);

    QObject::connect(&m_deleteCredentialJob, &QKeychain::DeletePasswordJob::finished, [=](){
        if (m_deleteCredentialJob.error()) {
            emit error(tr("Delete key failed: %1").arg(qPrintable(m_deleteCredentialJob.errorString())));
            return;
        }
        emit keyDeleted(key);
    });

    m_deleteCredentialJob.start();
}
