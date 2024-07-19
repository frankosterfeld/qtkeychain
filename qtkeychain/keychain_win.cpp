/******************************************************************************
 *   Copyright (C) 2011-2015 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"
#include "plaintextstore_p.h"

#include <comdef.h>
#include <windows.h>
#include <wincrypt.h>

#include <memory>

using namespace QKeychain;

namespace {
    QString formatWinError(unsigned long errorCode)
    {
        return QStringLiteral("WindowsError: %1: %2").arg(QString::number(errorCode, 16), QString::fromWCharArray(_com_error(errorCode).ErrorMessage()));
    }

    // decrpyted data, error
    std::pair<QByteArray, QString> unprotectData(const QByteArray &encrypted)
    {
        DATA_BLOB blob_in, blob_out;

        blob_in.pbData = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(encrypted.data()));
        blob_in.cbData = encrypted.size();

        if ( !CryptUnprotectData( &blob_in,
                                             nullptr,
                                             nullptr,
                                             nullptr,
                                             nullptr,
                                             0,
                                             &blob_out ) ) {
            return {{}, formatWinError(GetLastError())};
        }

        QByteArray decrypted( reinterpret_cast<char*>( blob_out.pbData ), blob_out.cbData );
        SecureZeroMemory( blob_out.pbData, blob_out.cbData );
        LocalFree( blob_out.pbData );
        return {decrypted, {}};
    }

    // encrypted data, error
    std::pair<QByteArray, QString> protectData(const QByteArray &data)
    {
        DATA_BLOB blob_in, blob_out;
        blob_in.pbData = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(data.data()));
        blob_in.cbData = data.size();
        if(!CryptProtectData( &blob_in,
                                           L"QKeychain-encrypted data",
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           0,
                                           &blob_out )) {

            return {{}, formatWinError(GetLastError())};
        }

        QByteArray encrypted( reinterpret_cast<char*>( blob_out.pbData ), blob_out.cbData );
        LocalFree( blob_out.pbData );
        return {encrypted, {}};
    }


}

#if defined(USE_CREDENTIAL_STORE)
#include <wincred.h>

void ReadPasswordJobPrivate::scheduledStart() {
    PCREDENTIALW cred;

    if (!CredReadW(reinterpret_cast<const wchar_t*>(key.utf16()), CRED_TYPE_GENERIC, 0, &cred)) {
        Error err;
        QString msg;
        switch(GetLastError()) {
        case ERROR_NOT_FOUND:
            err = EntryNotFound;
            msg = tr("Password entry not found");
            break;
        default:
            err = OtherError;
            msg = tr("Could not decrypt data");
            break;
        }

        q->emitFinishedWithError( err, msg );
        return;
    }

    data = QByteArray(reinterpret_cast<char*>(cred->CredentialBlob), cred->CredentialBlobSize);
    CredFree(cred);

    q->emitFinished();
}

void WritePasswordJobPrivate::scheduledStart() {
    CREDENTIALW cred = {};
    cred.Comment = const_cast<wchar_t*>(L"QtKeychain");
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<wchar_t*>(reinterpret_cast<const wchar_t*>(key.utf16()));
    cred.CredentialBlobSize = data.size();
    cred.CredentialBlob = reinterpret_cast<uchar*>(data.data());
    cred.Persist = CRED_PERSIST_ENTERPRISE;

    if (CredWriteW(&cred, 0)) {
        q->emitFinished();
        return;
    }

    const DWORD err = GetLastError();

    // Detect size-exceeded errors and provide nicer messages.
    // Unfortunately these error codes aren't documented.
    // Found empirically on Win10 1803 build 17134.523.
    if (err == RPC_X_BAD_STUB_DATA) {
        const size_t maxBlob = CRED_MAX_CREDENTIAL_BLOB_SIZE;
        if (cred.CredentialBlobSize > maxBlob) {
            q->emitFinishedWithError(
                OtherError,
                tr("Credential size exceeds maximum size of %1").arg(maxBlob));
            return;
        }
    }
    if (err == RPC_S_INVALID_BOUND) {
        const size_t maxTargetName = CRED_MAX_GENERIC_TARGET_NAME_LENGTH;
        if (key.size() > maxTargetName) {
            q->emitFinishedWithError(
                OtherError,
                tr("Credential key exceeds maximum size of %1").arg(maxTargetName));
            return;
        }
    }

    q->emitFinishedWithError( OtherError, tr("Writing credentials failed: Win32 error code %1").arg(err) );
}

void DeletePasswordJobPrivate::scheduledStart() {
    if (!CredDeleteW(reinterpret_cast<const wchar_t*>(key.utf16()), CRED_TYPE_GENERIC, 0)) {
        Error err;
        QString msg;
        switch(GetLastError()) {
        case ERROR_NOT_FOUND:
            err = EntryNotFound;
            msg = tr("Password entry not found");
            break;
        default:
            err = OtherError;
            msg = tr("Could not decrypt data");
            break;
        }

        q->emitFinishedWithError( err, msg );
    } else {
        q->emitFinished();
    }
}
#else
void ReadPasswordJobPrivate::scheduledStart() {
    PlainTextStore plainTextStore( q->service(), q->settings() );
    QByteArray encrypted = plainTextStore.readData( key );
    if ( plainTextStore.error() != NoError ) {
        q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
        return;
    }

    const auto result = unprotectData(encrypted);
    if (!result.second.isEmpty())
    {
        q->emitFinishedWithError( OtherError, tr("Could not decrypt data: %1").arg(result.second) );
        return;
    }
    data = result.first;
    q->emitFinished();
}

void WritePasswordJobPrivate::scheduledStart() {
    const auto result = protectData(data);
    if(!result.second.isEmpty())
    {
        q->emitFinishedWithError( OtherError,  tr("Encryption failed: %1").arg(result.second));
        return;
    }

    PlainTextStore plainTextStore( q->service(), q->settings() );
    plainTextStore.write( key, result.first, Binary );
    if ( plainTextStore.error() != NoError ) {
        q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
        return;
    }

    q->emitFinished();
}

void DeletePasswordJobPrivate::scheduledStart() {
    PlainTextStore plainTextStore( q->service(), q->settings() );
    plainTextStore.remove( key );
    if ( plainTextStore.error() != NoError ) {
        q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
    } else {
        q->emitFinished();
    }
}
#endif

bool QKeychain::isAvailable()
{
    return true;
}
