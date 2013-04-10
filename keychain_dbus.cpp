/******************************************************************************
 *   Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"

#include <QSettings>

#include <auto_ptr.h>

using namespace QKeychain;

class GnomeKeyring: private QLibrary {
public:
    typedef enum {
        RESULT_OK,
        RESULT_DENIED,
        RESULT_NO_KEYRING_DAEMON,
        RESULT_ALREADY_UNLOCKED,
        RESULT_NO_SUCH_KEYRING,
        RESULT_BAD_ARGUMENTS,
        RESULT_IO_ERROR,
        RESULT_CANCELLED,
        RESULT_KEYRING_ALREADY_EXISTS,
        RESULT_NO_MATCH
    } Result;
    typedef enum {
        ITEM_GENERIC_SECRET = 0,
        ITEM_NETWORK_PASSWORD,
        ITEM_NOTE,
        ITEM_CHAINED_KEYRING_PASSWORD,
        ITEM_ENCRYPTION_KEY_PASSWORD,
        ITEM_PK_STORAGE = 0x100
    } ItemType;
    typedef enum {
        ATTRIBUTE_TYPE_STRING,
        ATTRIBUTE_TYPE_UINT32
    } AttributeType;
    typedef char gchar;
    typedef void* gpointer;
    typedef struct {
        ItemType item_type;
        struct {
            const gchar* name;
            AttributeType type;
        } attributes[32];
    } PasswordSchema;
    typedef void ( *OperationGetStringCallback )( Result result, const char* string, gpointer data );
    typedef void ( *OperationDoneCallback )( Result result, gpointer data );
    typedef void ( *GDestroyNotify )( gpointer data );

    static const char* GNOME_KEYRING_DEFAULT;
    static const char* GNOME_KEYRING_SESSION;

    static bool isSupported()
    {
        GnomeKeyring& keyring = instance();
        return keyring.isLoaded() &&
               keyring.NETWORK_PASSWORD &&
               keyring.find_password &&
               keyring.store_password &&
               keyring.delete_password;
    }

    static gpointer store_network_password( const gchar* keyring, const gchar* display_name,
                                            const gchar* user, const gchar* server, const gchar* password,
                                            OperationDoneCallback callback, gpointer data, GDestroyNotify destroy_data )
    {
        if ( !isSupported() )
            return NULL;
        return instance().store_password( instance().NETWORK_PASSWORD,
                                          keyring, display_name, password, callback, data, destroy_data,
                                          "user", user, "server", server, NULL );
    }

    static gpointer find_network_password( const gchar* user, const gchar* server,
                                           OperationGetStringCallback callback, gpointer data, GDestroyNotify destroy_data )
    {
        if ( !isSupported() )
            return NULL;
        return instance().find_password( instance().NETWORK_PASSWORD,
                                         callback, data, destroy_data,
                                         "user", user, "server", server, NULL );
    }

    static gpointer delete_network_password( const gchar* user, const gchar* server,
                                             OperationDoneCallback callback, gpointer data, GDestroyNotify destroy_data )
    {
        if ( !isSupported() )
            return NULL;
        return instance().delete_password( instance().NETWORK_PASSWORD,
                                           callback, data, destroy_data,
                                           "user", user, "server", server, NULL );
    }

private:
    GnomeKeyring(): QLibrary("gnome-keyring", 0) {
        static const PasswordSchema schema = {
            ITEM_NETWORK_PASSWORD,
            {{ "user",   ATTRIBUTE_TYPE_STRING },
             { "server", ATTRIBUTE_TYPE_STRING },
             { NULL,     ( AttributeType )0 }}
        };
        NETWORK_PASSWORD = &schema;
        find_password =	reinterpret_cast<find_password_fn*>( resolve( "gnome_keyring_find_password" ) );
        store_password = reinterpret_cast<store_password_fn*>(resolve( "gnome_keyring_store_password" ) );
        delete_password = reinterpret_cast<delete_password_fn*>( resolve( "gnome_keyring_delete_password" ) );
    }

    static GnomeKeyring& instance() {
        static GnomeKeyring keyring;
        return keyring;
    }

    const PasswordSchema* NETWORK_PASSWORD;
    typedef gpointer ( store_password_fn )( const PasswordSchema* schema, const gchar* keyring,
                                            const gchar* display_name, const gchar* password,
                                            OperationDoneCallback callback, gpointer data, GDestroyNotify destroy_data,
                                            ... );
    typedef gpointer ( find_password_fn )( const PasswordSchema* schema,
                                           OperationGetStringCallback callback, gpointer data, GDestroyNotify destroy_data,
                                           ... );
    typedef gpointer ( delete_password_fn )( const PasswordSchema* schema,
                                             OperationDoneCallback callback, gpointer data, GDestroyNotify destroy_data,
                                             ... );
    find_password_fn* find_password;
    store_password_fn* store_password;
    delete_password_fn* delete_password;
};
const char* GnomeKeyring::GNOME_KEYRING_DEFAULT = NULL;
const char* GnomeKeyring::GNOME_KEYRING_SESSION = "session";

namespace QKeychain {
enum KeyringBackend {
    Backend_GnomeKeyring,
    Backend_Kwallet
};
static KeyringBackend detectKeyringBackend()
{
    if ( getenv( "GNOME_KEYRING_CONTROL" ) && GnomeKeyring::isSupported() )
        return Backend_GnomeKeyring;
    return Backend_Kwallet;
}
static KeyringBackend getKeyringBackend()
{
    static KeyringBackend backend = detectKeyringBackend();
    return backend;
}
}

void ReadPasswordJobPrivate::scheduledStart() {
    switch ( getKeyringBackend() ) {
    case Backend_GnomeKeyring:
        if ( !GnomeKeyring::find_network_password( key.toUtf8().constData(), q->service().toUtf8().constData(),
                                                   reinterpret_cast<GnomeKeyring::OperationGetStringCallback>( &ReadPasswordJobPrivate::gnomeKeyring_cb ),
                                                   this, NULL ) )
            q->emitFinishedWithError( OtherError, tr("Unknown error") );
        break;

    case Backend_Kwallet:
        iface = new org::kde::KWallet( QLatin1String("org.kde.kwalletd"), QLatin1String("/modules/kwalletd"), QDBusConnection::sessionBus(), this );
        const QDBusPendingReply<int> reply = iface->open( QLatin1String("kdewallet"), 0, q->service() );
        QDBusPendingCallWatcher* watcher = new QDBusPendingCallWatcher( reply, this );
        connect( watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(kwalletOpenFinished(QDBusPendingCallWatcher*)) );
        break;
    }
}

void ReadPasswordJobPrivate::gnomeKeyring_cb( int result, const char* string, ReadPasswordJobPrivate* self )
{
    switch ( (GnomeKeyring::Result)result ) {
    case GnomeKeyring::RESULT_OK:
        if ( self->dataType == ReadPasswordJobPrivate::Text )
            self->data = string;
        else
            self->data = QByteArray::fromBase64( string );
        self->q->emitFinished();
        break;

    case GnomeKeyring::RESULT_DENIED: self->q->emitFinishedWithError( AccessDenied, tr("Access to keychain denied") ); break;
    case GnomeKeyring::RESULT_NO_KEYRING_DAEMON: self->q->emitFinishedWithError( NoBackendAvailable, tr("No keyring daemon") ); break;
    case GnomeKeyring::RESULT_ALREADY_UNLOCKED: self->q->emitFinishedWithError( OtherError, tr("Already unlocked") ); break;
    case GnomeKeyring::RESULT_NO_SUCH_KEYRING: self->q->emitFinishedWithError( OtherError, tr("No such keyring") ); break;
    case GnomeKeyring::RESULT_BAD_ARGUMENTS: self->q->emitFinishedWithError( OtherError, tr("Bad arguments") ); break;
    case GnomeKeyring::RESULT_IO_ERROR: self->q->emitFinishedWithError( OtherError, tr("I/O error") ); break;
    case GnomeKeyring::RESULT_CANCELLED: self->q->emitFinishedWithError( OtherError, tr("Cancelled") ); break;
    case GnomeKeyring::RESULT_KEYRING_ALREADY_EXISTS: self->q->emitFinishedWithError( OtherError, tr("Keyring already exists") ); break;
    case GnomeKeyring::RESULT_NO_MATCH: self->q->emitFinishedWithError(  EntryNotFound, tr("No match") ); break;
    default: self->q->emitFinishedWithError( OtherError, tr("Unknown error") ); break;
    }
}

void ReadPasswordJobPrivate::kwalletOpenFinished( QDBusPendingCallWatcher* watcher ) {
    watcher->deleteLater();
    const QDBusPendingReply<int> reply = *watcher;

    std::auto_ptr<QSettings> local( !q->settings() ? new QSettings( q->service() ) : 0 );
    QSettings* actual = q->settings() ? q->settings() : local.get();
    WritePasswordJobPrivate::Mode mode;

    const QString typeKey = QString( "%1/type" ).arg( key );
    const QString dataKey = QString( "%1/data" ).arg( key );
    if ( reply.isError() ) {
        const QDBusError err = reply.error();

        if ( q->insecureFallback() && actual->contains( dataKey ) ) {

            mode = (WritePasswordJobPrivate::Mode)actual->value( typeKey ).toInt();
            data = actual->value( dataKey ).toByteArray();

            q->emitFinished();

            return;
        } else {
            if ( err.type() == QDBusError::ServiceUnknown ) //KWalletd not running
                q->emitFinishedWithError( NoBackendAvailable, tr("No keychain service available") );
            else
                q->emitFinishedWithError( OtherError, tr("Could not open wallet: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );

            return;
        }
    }

    if ( actual->contains( dataKey ) ) {
        // We previously stored data in the insecure QSettings, but now have KWallet available.
        // Do the migration

        data = actual->value( dataKey ).toByteArray();
        mode = (WritePasswordJobPrivate::Mode)actual->value( typeKey ).toInt();
        actual->remove( key );

        q->emitFinished();


        WritePasswordJob* j = new WritePasswordJob( q->service(), 0 );
        j->setSettings( q->settings() );
        j->setKey( key );
        j->setAutoDelete( true );
        if ( mode == WritePasswordJobPrivate::Binary )
            j->setBinaryData( data );
        else if ( mode == WritePasswordJobPrivate::Text )
            j->setTextData( QString::fromUtf8( data ) );
        else
            Q_ASSERT( false );

        j->start();

        return;
    }

    walletHandle = reply.value();

    if ( walletHandle < 0 ) {
        q->emitFinishedWithError( AccessDenied, tr("Access to keychain denied") );
        return;
    }

    const QDBusPendingReply<int> nextReply = iface->entryType( walletHandle, q->service(), key, q->service() );
    QDBusPendingCallWatcher* nextWatcher = new QDBusPendingCallWatcher( nextReply, this );
    connect( nextWatcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(kwalletEntryTypeFinished(QDBusPendingCallWatcher*)) );
}

void ReadPasswordJobPrivate::kwalletEntryTypeFinished( QDBusPendingCallWatcher* watcher ) {
    watcher->deleteLater();
    if ( watcher->isError() ) {
        const QDBusError err = watcher->error();
        q->emitFinishedWithError( OtherError, tr("Could not determine data type: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );
        return;
    }

    const QDBusPendingReply<int> reply = *watcher;

    dataType = reply.value() == 1/*Password*/ ? Text : Binary;

    const QDBusPendingCall nextReply = dataType == Text
        ? QDBusPendingCall( iface->readPassword( walletHandle, q->service(), key, q->service() ) )
        : QDBusPendingCall( iface->readEntry( walletHandle, q->service(), key, q->service() ) );
    QDBusPendingCallWatcher* nextWatcher = new QDBusPendingCallWatcher( nextReply, this );
    connect( nextWatcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(kwalletReadFinished(QDBusPendingCallWatcher*)) );
}

void ReadPasswordJobPrivate::kwalletReadFinished( QDBusPendingCallWatcher* watcher ) {
    watcher->deleteLater();
    if ( watcher->isError() ) {
        const QDBusError err = watcher->error();
        q->emitFinishedWithError( OtherError, tr("Could not read password: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );
        return;
    }

    if ( dataType == Binary ) {
        QDBusPendingReply<QByteArray> reply = *watcher;
        data = reply.value();
    } else {
        QDBusPendingReply<QString> reply = *watcher;
        data = reply.value().toUtf8();
    }
    q->emitFinished();
}

void WritePasswordJobPrivate::scheduledStart() {
    switch ( getKeyringBackend() ) {
    case Backend_GnomeKeyring:
        if ( mode == WritePasswordJobPrivate::Delete ) {
            if ( !GnomeKeyring::delete_network_password( key.toUtf8().constData(), q->service().toUtf8().constData(),
                                                         reinterpret_cast<GnomeKeyring::OperationDoneCallback>( &WritePasswordJobPrivate::gnomeKeyring_cb ),
                                                         this, NULL ) )
                q->emitFinishedWithError( OtherError, tr("Unknown error") );
        } else {
            QByteArray password = mode == WritePasswordJobPrivate::Text ? textData.toUtf8() : binaryData.toBase64();
            QByteArray service = q->service().toUtf8();
            if ( !GnomeKeyring::store_network_password( GnomeKeyring::GNOME_KEYRING_DEFAULT, service.constData(),
                                                        key.toUtf8().constData(), service.constData(), password.constData(),
                                                        reinterpret_cast<GnomeKeyring::OperationDoneCallback>( &WritePasswordJobPrivate::gnomeKeyring_cb ),
                                                        this, NULL ) )
                q->emitFinishedWithError( OtherError, tr("Unknown error") );
        }
        break;

    case Backend_Kwallet:
        iface = new org::kde::KWallet( QLatin1String("org.kde.kwalletd"), QLatin1String("/modules/kwalletd"), QDBusConnection::sessionBus(), this );
        const QDBusPendingReply<int> reply = iface->open( QLatin1String("kdewallet"), 0, q->service() );
        QDBusPendingCallWatcher* watcher = new QDBusPendingCallWatcher( reply, this );
        connect( watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(kwalletOpenFinished(QDBusPendingCallWatcher*)) );
        break;
    }
}

void WritePasswordJobPrivate::gnomeKeyring_cb( int result, WritePasswordJobPrivate* self )
{
    switch ( (GnomeKeyring::Result)result ) {
    case GnomeKeyring::RESULT_OK: self->q->emitFinished(); break; 
    case GnomeKeyring::RESULT_DENIED: self->q->emitFinishedWithError( AccessDenied, tr("Access to keychain denied") ); break;
    case GnomeKeyring::RESULT_NO_KEYRING_DAEMON: self->q->emitFinishedWithError( NoBackendAvailable, tr("No keyring daemon") ); break;
    case GnomeKeyring::RESULT_ALREADY_UNLOCKED: self->q->emitFinishedWithError( OtherError, tr("Already unlocked") ); break;
    case GnomeKeyring::RESULT_NO_SUCH_KEYRING: self->q->emitFinishedWithError( OtherError, tr("No such keyring") ); break;
    case GnomeKeyring::RESULT_BAD_ARGUMENTS: self->q->emitFinishedWithError( OtherError, tr("Bad arguments") ); break;
    case GnomeKeyring::RESULT_IO_ERROR: self->q->emitFinishedWithError( OtherError, tr("I/O error") ); break;
    case GnomeKeyring::RESULT_CANCELLED: self->q->emitFinishedWithError( OtherError, tr("Cancelled") ); break;
    case GnomeKeyring::RESULT_KEYRING_ALREADY_EXISTS: self->q->emitFinishedWithError( OtherError, tr("Keyring already exists") ); break;
    case GnomeKeyring::RESULT_NO_MATCH: self->q->emitFinishedWithError(  EntryNotFound, tr("No match") ); break;
    default: self->q->emitFinishedWithError( OtherError, tr("Unknown error") ); break;
    }
}

void WritePasswordJobPrivate::kwalletOpenFinished( QDBusPendingCallWatcher* watcher ) {
    watcher->deleteLater();
    QDBusPendingReply<int> reply = *watcher;

    std::auto_ptr<QSettings> local( !q->settings() ? new QSettings(  q->service() ) : 0 );
    QSettings* actual = q->settings() ? q->settings() : local.get();

    if ( reply.isError() ) {
        if ( q->insecureFallback() ) {
            if ( mode == Delete ) {
                actual->remove( key );
                actual->sync();

                q->emitFinished();
                return;
            }

            actual->setValue( QString( "%1/type" ).arg( key ), (int)mode );
            if ( mode == Text )
                actual->setValue( QString( "%1/data" ).arg( key ), textData.toUtf8() );
            else if ( mode == Binary )
                actual->setValue( QString( "%1/data" ).arg( key ), binaryData );
            actual->sync();

            q->emitFinished();
        } else {
            const QDBusError err = reply.error();
            q->emitFinishedWithError( OtherError, tr("Could not open wallet: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );
        }
        return;
    }

    if ( actual->contains( key ) )
    {
        // If we had previously written to QSettings, but we now have a kwallet available, migrate and delete old insecure data
        actual->remove( key );
        actual->sync();
    }

    const int handle = reply.value();

    if ( handle < 0 ) {
        q->emitFinishedWithError( AccessDenied, tr("Access to keychain denied") );
        return;
    }

    QDBusPendingReply<int> nextReply;

    if ( !textData.isEmpty() )
        nextReply = iface->writePassword( handle, q->service(), key, textData, q->service() );
    else if ( !binaryData.isEmpty() )
        nextReply = iface->writeEntry( handle, q->service(), key, binaryData, q->service() );
    else
        nextReply = iface->removeEntry( handle, q->service(), key, q->service() );

    QDBusPendingCallWatcher* nextWatcher = new QDBusPendingCallWatcher( nextReply, this );
    connect( nextWatcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(kwalletWriteFinished(QDBusPendingCallWatcher*)) );
}

void WritePasswordJobPrivate::kwalletWriteFinished( QDBusPendingCallWatcher* watcher ) {
    watcher->deleteLater();
    QDBusPendingReply<int> reply = *watcher;
    if ( reply.isError() ) {
        const QDBusError err = reply.error();
        q->emitFinishedWithError( OtherError, tr("Could not open wallet: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );
        return;
    }

    q->emitFinished();
}
