QtKeychain
==========

QtKeychain is a Qt API to store passwords and other secret data securely. How the data is stored depends on the platform:

 * **macOS:** Passwords are stored in the macOS Keychain. On macOS 10.15 and newer, the data protection keychain
   is used if the application is signed accordingly, otherwise the file-based keychain
   (see [Data protection keychain on macOS](#data-protection-keychain-on-macos)).

 * **Linux/Unix:** If running, GNOME Keyring is used, otherwise QtKeychain tries to use KWallet (via D-Bus), if available. Libsecret (common API for desktop-specific solutions)
   is also supported.

 * **WebAssembly:** Passwords are managed using a transient HTML bridge form, enabling the browser's native password manager (auto-fill and "Save Password" prompts) and the Credential Management API (`navigator.credentials`).

 * **Windows:** By default, the Windows Credential Store is used (requires Windows 7 or newer).
Pass `-DUSE_CREDENTIAL_STORE=OFF` to cmake to disable it. If disabled, QtKeychain uses the Windows API function
[CryptProtectData](http://msdn.microsoft.com/en-us/library/windows/desktop/aa380261%28v=vs.85%29.aspx "CryptProtectData function")
to encrypt the password with the user's logon credentials. The encrypted data is then persisted via QSettings.

 * **Android and iOS:** Passwords are stored in the Android keystore system and iOS keychain, respectively.

In unsupported environments QtKeychain will report an error. It will not store any data unencrypted unless explicitly requested (`setInsecureFallback( true )`).


Requirements
------------

QtKeychain 0.12 and newer supports Qt 5 and Qt 6 and requires a compiler with C++11 support. Older versions support Qt 4 and Qt 5.

Data protection keychain on macOS
---------------------------------

macOS has two keychain implementations: the legacy, file-based keychain and the data protection keychain
(macOS 10.15 and newer, the same implementation as on iOS). Which one QtKeychain uses is controlled per job via
`Job::setMacOSKeychainPreference()`:

 * `DataProtectionKeychainWithLegacyFallback` (default): Use the data protection keychain. Entries not found there
   are looked up in the file-based keychain and migrated to the data protection keychain.
 * `DataProtectionKeychain`: Use the data protection keychain only.
 * `LegacyKeychain`: Use the file-based keychain only (behavior of QtKeychain 0.17 and older).

The data protection keychain can only be used by applications that are code-signed with an application identifier
entitlement, which in turn must be backed by a provisioning profile. If that is not the case, QtKeychain falls back
to the file-based keychain.

Thus, depending on how the application is built and distributed:

 * **Mac App Store:** Works out of the box, as App Store builds are signed with a provisioning profile and the
   application identifier.
 * **Developer ID (notarized, e.g. distributed as DMG):** Requires an App ID and a Developer ID provisioning profile
   from the Apple Developer portal. Embed the profile and include in the entitlements:

   ```xml
   <key>com.apple.application-identifier</key>
   <string>TEAMID.com.example.myapp</string>
   <key>com.apple.developer.team-identifier</key>
   <string>TEAMID</string>
   <key>keychain-access-groups</key>
   <array>
       <string>TEAMID.com.example.myapp</string>
   </array>
   ```

   ```
   codesign --force --options runtime --timestamp --entitlements myapp.entitlements \
            --sign "Developer ID Application: ..." MyApp.app
   ```

 * **Unsigned or ad-hoc signed builds (e.g. local development builds) and command-line tools**
   The data protection keychain is not available, the file-based keychain is used.

Notes:

 * Entries in the data protection keychain belong to the keychain access group (by default the application
   identifier, i.e. team ID and bundle identifier). Changing the team or bundle identifier makes existing entries
   inaccessible.
 * Development builds (file-based keychain) and release builds (data protection keychain) don't see each other's
   entries, except that release builds move entries from the file-based keychain to the data protection keychain
   on first read (after which development builds no longer find them).

License
-------

QtKeychain is available under the [Modified BSD License](http://www.gnu.org/licenses/license-list.html#ModifiedBSD). See the file COPYING for details.
