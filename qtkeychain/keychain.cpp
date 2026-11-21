/******************************************************************************
 *   Copyright (C) 2011-2015 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain.h"
#include "keychain_p.h"

using namespace QKeychain;

Job::Job(JobPrivate *q, QObject *parent) : QObject(parent), d(q) { }

Job::~Job()
{
    delete d;
}

QString Job::service() const
{
    return d->service;
}

QSettings *Job::settings() const
{
    return d->settings;
}

void Job::setSettings(QSettings *settings)
{
    d->settings = settings;
}

void Job::start()
{
    QMetaObject::invokeMethod(this, "doStart", Qt::QueuedConnection);
}

bool Job::autoDelete() const
{
    return d->autoDelete;
}

void Job::setAutoDelete(bool autoDelete)
{
    d->autoDelete = autoDelete;
}

bool Job::insecureFallback() const
{
    return d->insecureFallback;
}

void Job::setInsecureFallback(bool insecureFallback)
{
    d->insecureFallback = insecureFallback;
}

MacOSKeychainPreference Job::macOSKeychainPreference() const
{
    return d->macOSKeychainPreference;
}

void Job::setMacOSKeychainPreference(MacOSKeychainPreference preference)
{
    d->macOSKeychainPreference = preference;
}

void Job::doStart()
{
    JobExecutor::instance()->enqueue(this);
}

void Job::emitFinished()
{
    emit finished(this);
    if (d->autoDelete)
        deleteLater();
}

void Job::emitFinishedWithError(Error error, const QString &errorString)
{
    d->error = error;
    d->errorString = errorString;
    emitFinished();
}

void Job::scheduledStart()
{
    if (d->service.isEmpty() && d->key.isEmpty()) {
        emitFinishedWithError(EntryNotFound, tr("Both service name and key are empty"));
        return;
    }
    d->scheduledStart();
}

Error Job::error() const
{
    return d->error;
}

QString Job::errorString() const
{
    return d->errorString;
}

void Job::setError(Error error)
{
    d->error = error;
}

void Job::setErrorString(const QString &errorString)
{
    d->errorString = errorString;
}

ReadPasswordJob::ReadPasswordJob(const QString &service, QObject *parent)
    : Job(new ReadPasswordJobPrivate(service, this), parent)
{
}

ReadPasswordJob::~ReadPasswordJob() { }

namespace {

static QString decodeTextData(const QByteArray &data)
{
    if (data.isEmpty())
        return QString();

    // Check for UTF-16LE BOM
    if (data.size() >= 2 && static_cast<uchar>(data.at(0)) == 0xFF && static_cast<uchar>(data.at(1)) == 0xFE) {
        QString result;
        const auto len = (data.size() - 2) / 2;
        result.reserve(len);
        for (auto i = 0; i < len; ++i) {
            const quint16 code = static_cast<quint8>(data.at(2 + 2 * i)) |
                                 (static_cast<quint8>(data.at(2 + 2 * i + 1)) << 8);
            result.append(QChar(code));
        }
        while (result.endsWith(QChar(0)))
            result.chop(1);
        return result;
    }

    // Check for UTF-16BE BOM
    if (data.size() >= 2 && static_cast<uchar>(data.at(0)) == 0xFE && static_cast<uchar>(data.at(1)) == 0xFF) {
        QString result;
        const auto len = (data.size() - 2) / 2;
        result.reserve(len);
        for (auto i = 0; i < len; ++i) {
            const quint16 code = (static_cast<quint8>(data.at(2 + 2 * i)) << 8) |
                                 static_cast<quint8>(data.at(2 + 2 * i + 1));
            result.append(QChar(code));
        }
        while (result.endsWith(QChar(0)))
            result.chop(1);
        return result;
    }

    // Check for UTF-8 BOM
    if (data.size() >= 3 && static_cast<uchar>(data.at(0)) == 0xEF &&
        static_cast<uchar>(data.at(1)) == 0xBB && static_cast<uchar>(data.at(2)) == 0xBF) {
        QString result = QString::fromUtf8(data.constData() + 3, data.size() - 3);
        while (result.endsWith(QChar(0)))
            result.chop(1);
        return result;
    }

    // Check for UTF-16LE without BOM (common on Windows, e.g. cmdkey / Credential Manager)
    // In UTF-16LE for ASCII characters, odd-indexed bytes are 0x00.
    if (data.size() % 2 == 0 && data.size() >= 2 && data.at(1) == '\0') {
        QString result;
        const auto len = data.size() / 2;
        result.reserve(len);
        for (auto i = 0; i < len; ++i) {
            const quint16 code = static_cast<quint8>(data.at(2 * i)) |
                                 (static_cast<quint8>(data.at(2 * i + 1)) << 8);
            result.append(QChar(code));
        }
        while (result.endsWith(QChar(0)))
            result.chop(1);
        return result;
    }

    // Try decoding as UTF-8
    QString result = QString::fromUtf8(data);

    // If UTF-8 decoding contains replacement characters, or contains embedded control characters
    // (indicating Cyrillic/Hebrew/Arabic in UTF-16LE without BOM), and byte length is even, try UTF-16LE.
    bool looksLikeUtf16 = false;
    if (data.size() % 2 == 0 && data.size() >= 2) {
        if (result.contains(QChar::ReplacementCharacter)) {
            looksLikeUtf16 = true;
        } else {
            QString stripped = result;
            while (stripped.endsWith(QChar(0)))
                stripped.chop(1);
            for (int i = 0; i < stripped.size(); ++i) {
                const ushort u = stripped.at(i).unicode();
                if (u < 0x20 && u != 0x09 && u != 0x0A && u != 0x0D) {
                    looksLikeUtf16 = true;
                    break;
                }
            }
        }
    }

    if (looksLikeUtf16) {
        QString utf16Result;
        const auto len = data.size() / 2;
        utf16Result.reserve(len);
        for (auto i = 0; i < len; ++i) {
            const quint16 code = static_cast<quint8>(data.at(2 * i)) |
                                 (static_cast<quint8>(data.at(2 * i + 1)) << 8);
            utf16Result.append(QChar(code));
        }
        while (utf16Result.endsWith(QChar(0)))
            utf16Result.chop(1);
        return utf16Result;
    }

    while (result.endsWith(QChar(0)))
        result.chop(1);
    return result;
}

} // namespace

QString ReadPasswordJob::textData() const
{
    return decodeTextData(d->data);
}

QByteArray ReadPasswordJob::binaryData() const
{
    return d->data;
}

QString Job::key() const
{
    return d->key;
}

void Job::setKey(const QString &key_)
{
    d->key = key_;
}

WritePasswordJob::WritePasswordJob(const QString &service, QObject *parent)
    : Job(new WritePasswordJobPrivate(service, this), parent)
{
}

WritePasswordJob::~WritePasswordJob() { }

void WritePasswordJob::setBinaryData(const QByteArray &data)
{
    d->data = data;
    d->mode = JobPrivate::Binary;
}

void WritePasswordJob::setTextData(const QString &data)
{
    d->data = data.toUtf8();
    d->mode = JobPrivate::Text;
}

DeletePasswordJob::DeletePasswordJob(const QString &service, QObject *parent)
    : Job(new DeletePasswordJobPrivate(service, this), parent)
{
}

DeletePasswordJob::~DeletePasswordJob() { }

DeletePasswordJobPrivate::DeletePasswordJobPrivate(const QString &service_, DeletePasswordJob *qq)
    : JobPrivate(service_, qq)
{
}

JobExecutor::JobExecutor() : QObject(nullptr), m_jobRunning(false) { }

void JobExecutor::enqueue(Job *job)
{
    m_queue.enqueue(job);
    startNextIfNoneRunning();
}

void JobExecutor::startNextIfNoneRunning()
{
    if (m_queue.isEmpty() || m_jobRunning)
        return;
    QPointer<Job> next;
    while (!next && !m_queue.isEmpty()) {
        next = m_queue.dequeue();
    }
    if (next) {
        connect(next, &Job::finished, this, &JobExecutor::jobFinished);
        connect(next, &Job::destroyed, this, &JobExecutor::jobDestroyed);
        m_jobRunning = true;
        next->scheduledStart();
    }
}

void JobExecutor::jobDestroyed(QObject *object)
{
    object->disconnect(this);
    m_jobRunning = false;
    startNextIfNoneRunning();
}

void JobExecutor::jobFinished(Job *job)
{
    Q_UNUSED(job) // for release mode
    job->disconnect(this);
    m_jobRunning = false;
    startNextIfNoneRunning();
}

JobExecutor *JobExecutor::s_instance = nullptr;

JobExecutor *JobExecutor::instance()
{
    if (!s_instance)
        s_instance = new JobExecutor;
    return s_instance;
}

ReadPasswordJobPrivate::ReadPasswordJobPrivate(const QString &service_, ReadPasswordJob *qq)
    : JobPrivate(service_, qq)
{
}

JobPrivate::JobPrivate(const QString &service_, Job *qq)
    : q(qq),
      mode(Text),
      error(NoError),
      service(service_),
      autoDelete(true),
      insecureFallback(false),
      macOSKeychainPreference(MacOSKeychainPreference::DataProtectionKeychainWithLegacyFallback)
{
}

QString JobPrivate::modeToString(Mode m)
{
    switch (m) {
    case Text:
        return QLatin1String("Text");
    case Binary:
        return QLatin1String("Binary");
    case Map:
        return QLatin1String("Map");
    }

    Q_ASSERT_X(false, Q_FUNC_INFO, "Unhandled Mode value");
    return QString();
}

JobPrivate::Mode JobPrivate::stringToMode(const QString &s)
{
    if (s == QLatin1String("Text") || s == QLatin1String("1"))
        return Text;
    if (s == QLatin1String("Binary") || s == QLatin1String("2"))
        return Binary;
    if (s == QLatin1String("Map"))
        return Map;
    qCritical("Unexpected mode string '%s'", qPrintable(s));

    return Text;
}

WritePasswordJobPrivate::WritePasswordJobPrivate(const QString &service_, WritePasswordJob *qq)
    : JobPrivate(service_, qq)
{
}
