/******************************************************************************
 *   Copyright (C) 2012 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#ifndef QTKEYCHAIN_KEYCHAIN_DBUS_P_H
#define QTKEYCHAIN_KEYCHAIN_DBUS_P_H

#include "keychain.h"

#include <QPointer>
#include <QVector>

namespace QKeychain {

class JobExecutor : public QObject {
    Q_OBJECT
public:

    static JobExecutor* instance();

    void enqueue( Job* job );

private:
    explicit JobExecutor();
    void startNextIfNoneRunning();

private Q_SLOTS:
    void jobFinished( QKeychain::Job* );
    void jobDestroyed( QObject* object );

private:
    static JobExecutor* s_instance;
    Job* m_runningJob;
    QVector<QPointer<Job> > m_queue;
};

}

#endif

