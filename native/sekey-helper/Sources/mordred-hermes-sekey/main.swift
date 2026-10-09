// mordred-hermes-sekey — Secure Enclave helper CLI (CryptoKit file-store).
//
// One process invocation == one operation. Reads a single JSON request
// object from stdin, performs the Secure Enclave operation, writes a single
// JSON response object to stdout, and exits (0 on success, 1 on error).
//
// The Python side (`mordred_hermes.keyvault._seckey_helper`) spawns this
// binary once per `_SecKeyOps` method call. This binary is policy-free: it
// receives the application tag as hex bytes and uses it verbatim as the
// store filename, so the cleartext key_id never crosses the process boundary
// (the tag is a SHA-256 prefix computed Python-side).
//
// Requests (stdin):
//   {"cmd":"generate","tag_hex":"..","label":"..","unattended":false}
//   {"cmd":"public_key","tag_hex":".."}
//   {"cmd":"delete","tag_hex":".."}
//   {"cmd":"ecdh","tag_hex":"..","peer_pub_hex":".."}
//   {"cmd":"probe"}
//   {"cmd":"anchor_get","account":".."}
//   {"cmd":"anchor_add","account":"..","value_hex":".."}
//   {"cmd":"anchor_set","account":"..","value_hex":".."}
//   {"cmd":"anchor_delete","account":".."}
//
// The anchor_* commands keep the vault's freshness anchor (a small non-secret
// record) in a login-keychain generic-password item that THIS binary creates
// and reads. A legacy keychain item trusts only the binary that created it;
// when the Python interpreter wrote it, every other interpreter (a dev venv,
// Hermes's managed Python, an upgraded Python) triggered a keychain password
// dialog on each access. One helper binary serves every Python process, so the
// item's ACL keeps matching. The service name is fixed below: the helper can
// only address Mordred's own anchor items, never an arbitrary keychain item.
//
// "unattended" (generate only, default false): when false the key is created
// with a Touch-ID/passcode-gated access control, so every ECDH prompts. When
// true the key carries only .privateKeyUsage — it stays Enclave-bound (cannot
// be exfiltrated to another machine) but ECDH runs WITHOUT a prompt as long as
// the session is unlocked, for autonomous use. The choice is baked into the
// key's dataRepresentation at generation time and cannot change afterward.
// Success (stdout, exit 0):
//   {"public_key_hex":"04.."}   {"shared_hex":".."}   {"ok":true}   {"value_hex":".."}
// Failure (stdout, exit 1):
//   {"error":{"domain":"OSStatus","status":-25300,"message":".."}}
//
// Persistence model: each key is a CryptoKit `SecureEnclave.P256.KeyAgreement`
// private key. We store its `dataRepresentation` — an opaque blob that ONLY
// this device's Secure Enclave can decrypt and use — in a plain file at
// `<store>/<tag_hex>.bin`. No Keychain, no keychain-access-groups entitlement,
// no provisioning profile, no .app bundle: an ad-hoc-signed bare CLI works.
// The blob is useless without the originating Enclave, so the file at rest
// leaks nothing. ECDH triggers the Touch ID / passcode prompt because the key
// is generated with a `.biometryCurrentSet` access control; reading the public
// key does not.

import CryptoKit
import Darwin
import Foundation
import Security

// MARK: - OSStatus mirror
//
// We re-emit the same OSStatus ints the legacy Keychain path used so the
// Python `_translate_error` table keeps working unchanged across the boundary.

let errItemNotFound = -25300   // errSecItemNotFound
let errDuplicateItem = -25299  // errSecDuplicateItem
let errAuthFailed = -25293     // errSecAuthFailed

// MARK: - Wire types

struct Request: Decodable {
    let cmd: String
    let tag_hex: String?
    let label: String?
    let peer_pub_hex: String?
    let unattended: Bool?
    let account: String?
    let value_hex: String?
}

struct HelperError: Error {
    let domain: String
    let status: Int
    let message: String
}

// MARK: - hex helpers

func hexDecode(_ s: String) -> Data? {
    guard s.count % 2 == 0 else { return nil }
    var out = Data(capacity: s.count / 2)
    var idx = s.startIndex
    while idx < s.endIndex {
        let next = s.index(idx, offsetBy: 2)
        guard let byte = UInt8(s[idx..<next], radix: 16) else { return nil }
        out.append(byte)
        idx = next
    }
    return out
}

func hexEncode(_ d: Data) -> String {
    d.map { String(format: "%02x", $0) }.joined()
}

// MARK: - Blob store
//
// Resolution order for the store directory:
//   1. MORDRED_SEKEY_STORE — explicit absolute directory (authoritative).
//   2. $HERMES_HOME/mordred/keyvault/sekey
//   3. ~/.hermes/mordred/keyvault/sekey
// This mirrors mordred_hermes._home.hermes_home so the SE blobs live under
// the same keyvault tree the Python side uses for everything else.

func storeDir() -> URL {
    let env = ProcessInfo.processInfo.environment
    if let explicit = env["MORDRED_SEKEY_STORE"], !explicit.isEmpty {
        return URL(fileURLWithPath: (explicit as NSString).expandingTildeInPath, isDirectory: true)
    }
    let base: URL
    if let hermesHome = env["HERMES_HOME"], !hermesHome.isEmpty {
        base = URL(fileURLWithPath: (hermesHome as NSString).expandingTildeInPath, isDirectory: true)
    } else {
        base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".hermes", isDirectory: true)
    }
    return base
        .appendingPathComponent("mordred", isDirectory: true)
        .appendingPathComponent("keyvault", isDirectory: true)
        .appendingPathComponent("sekey", isDirectory: true)
}

func blobURL(tagHex: String) -> URL {
    storeDir().appendingPathComponent("\(tagHex).bin", isDirectory: false)
}

func openValidatedStoreDirectory() throws -> Int32 {
    let dir = storeDir()
    let fd = dir.path.withCString {
        open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard fd >= 0 else {
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to open store dir safely: \(String(cString: strerror(errno)))"
        )
    }
    var info = stat()
    if fstat(fd, &info) != 0 {
        let message = String(cString: strerror(errno))
        _ = close(fd)
        throw HelperError(domain: "helper", status: -1, message: "failed to inspect store dir: \(message)")
    }
    guard (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) else {
        _ = close(fd)
        throw HelperError(domain: "helper", status: -1, message: "store path is not a real directory")
    }
    let permissions = info.st_mode & mode_t(0o777)
    guard permissions == mode_t(0o700) else {
        _ = close(fd)
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "store directory must be mode 0700 (got \(String(permissions, radix: 8)))"
        )
    }
    return fd
}

func ensureStoreDir() throws {
    let dir = storeDir()
    do {
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    } catch {
        throw HelperError(domain: "helper", status: -1, message: "failed to create store dir: \(error.localizedDescription)")
    }
    // createDirectory is idempotent and follows an existing symlink. Bind the
    // postcondition to an O_NOFOLLOW directory descriptor and reject loose or
    // non-directory objects before creating/reading any key blob.
    let fd = try openValidatedStoreDirectory()
    _ = close(fd)
}

func withStoreLock<T>(_ body: () throws -> T) throws -> T {
    try ensureStoreDir()
    let lockURL = storeDir().appendingPathComponent(".lock", isDirectory: false)
    let flags = O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW
    let fd = lockURL.path.withCString {
        open($0, flags, mode_t(0o600))
    }
    guard fd >= 0 else {
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to open store lock: \(String(cString: strerror(errno)))"
        )
    }
    var lockInfo = stat()
    if fstat(fd, &lockInfo) != 0 || (lockInfo.st_mode & mode_t(S_IFMT)) != mode_t(S_IFREG) {
        let message = String(cString: strerror(errno))
        _ = close(fd)
        throw HelperError(domain: "helper", status: -1, message: "store lock is not a regular file: \(message)")
    }
    if fchmod(fd, mode_t(0o600)) != 0 {
        let message = String(cString: strerror(errno))
        _ = close(fd)
        throw HelperError(domain: "helper", status: -1, message: "failed to secure store lock: \(message)")
    }
    if flock(fd, LOCK_EX) != 0 {
        let message = String(cString: strerror(errno))
        _ = close(fd)
        throw HelperError(domain: "helper", status: -1, message: "failed to acquire store lock: \(message)")
    }
    defer {
        _ = flock(fd, LOCK_UN)
        _ = close(fd)
    }
    return try body()
}

func emitStoreWarning(_ message: String) {
    guard let data = "mordred-hermes-sekey: \(message)\n".data(using: .utf8) else { return }
    FileHandle.standardError.write(data)
}

func createStagingBlob(tagHex: String) throws -> (url: URL, fd: Int32) {
    let dir = storeDir()
    for _ in 0..<128 {
        let name = ".\(tagHex).tmp-\(getpid())-\(UUID().uuidString)"
        let url = dir.appendingPathComponent(name, isDirectory: false)
        let flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW
        let fd = url.path.withCString {
            open($0, flags, mode_t(0o600))
        }
        if fd >= 0 {
            return (url, fd)
        }
        let errorNumber = errno
        if errorNumber == EEXIST {
            continue
        }
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to create blob staging file: \(String(cString: strerror(errorNumber)))"
        )
    }
    throw HelperError(domain: "helper", status: -1, message: "failed to allocate a unique blob staging file")
}

func durableSync(_ fd: Int32, description: String) throws {
    // On macOS fsync(2) may stop at the drive's volatile write cache.
    // F_FULLFSYNC asks the device to flush through to stable media. Fall back
    // only when the filesystem does not implement it; a real I/O failure must
    // propagate instead of being hidden by a weaker second call.
    if fcntl(fd, F_FULLFSYNC) == 0 {
        return
    }
    let fullSyncError = errno
    if fullSyncError != ENOTSUP && fullSyncError != EINVAL {
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to durably sync \(description): \(String(cString: strerror(fullSyncError)))"
        )
    }
    if fsync(fd) != 0 {
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to sync \(description): \(String(cString: strerror(errno)))"
        )
    }
}

func syncStoreDirectory() throws {
    let fd = try openValidatedStoreDirectory()
    defer { _ = close(fd) }
    try durableSync(fd, description: "store directory")
}

func syncStoreDirectoryBestEffort(context: String) {
    do {
        try syncStoreDirectory()
    } catch {
        emitStoreWarning("\(context), but the store directory could not be synced: \(error)")
    }
}

func writeBlob(_ blob: Data, tagHex: String) throws {
    try ensureStoreDir()
    let target = blobURL(tagHex: tagHex)
    let staging = try createStagingBlob(tagHex: tagHex)
    var fdOpen = true
    var stagingPresent = true
    defer {
        if fdOpen {
            _ = close(staging.fd)
        }
        if stagingPresent {
            _ = staging.url.path.withCString { unlink($0) }
        }
    }

    if fchmod(staging.fd, mode_t(0o600)) != 0 {
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to secure blob staging file: \(String(cString: strerror(errno)))"
        )
    }
    try blob.withUnsafeBytes { bytes in
        guard let base = bytes.baseAddress else { return }
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(staging.fd, base.advanced(by: offset), bytes.count - offset)
            if written < 0 {
                if errno == EINTR {
                    continue
                }
                throw HelperError(
                    domain: "helper",
                    status: -1,
                    message: "failed to write blob staging file: \(String(cString: strerror(errno)))"
                )
            }
            if written == 0 {
                throw HelperError(
                    domain: "helper",
                    status: -1,
                    message: "failed to write blob staging file: write returned no progress"
                )
            }
            offset += written
        }
    }
    try durableSync(staging.fd, description: "blob staging file")
    _ = close(staging.fd)
    fdOpen = false

    let linkResult = staging.url.path.withCString { source in
        target.path.withCString { destination in
            link(source, destination)
        }
    }
    if linkResult != 0 {
        let errorNumber = errno
        if errorNumber == EEXIST {
            throw HelperError(domain: "OSStatus", status: errDuplicateItem, message: "key already exists for tag")
        }
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to publish blob: \(String(cString: strerror(errorNumber)))"
        )
    }

    // The link is visible but is not a durable commit until its parent
    // directory is synced. If this fails, report an indeterminate generation
    // failure: Python must not commit metadata/ciphertext for a key whose
    // authoritative name can disappear after power loss. The visible orphan
    // is intentionally left for explicit reset/remediation.
    try syncStoreDirectory()
    let unlinkResult = staging.url.path.withCString { unlink($0) }
    if unlinkResult == 0 || errno == ENOENT {
        stagingPresent = false
    } else {
        emitStoreWarning(
            "key blob was published, but its private staging name could not be removed: "
                + String(cString: strerror(errno))
        )
    }
    syncStoreDirectoryBestEffort(context: "key blob is available after staging cleanup")
}

func readBlob(tagHex: String) throws -> Data {
    try ensureStoreDir()
    let url = blobURL(tagHex: tagHex)
    let fd = url.path.withCString {
        open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
    }
    guard fd >= 0 else {
        if errno == ENOENT {
            throw HelperError(domain: "OSStatus", status: errItemNotFound, message: "no key for tag")
        }
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to open blob safely: \(String(cString: strerror(errno)))"
        )
    }
    defer { _ = close(fd) }

    var info = stat()
    guard fstat(fd, &info) == 0 else {
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "failed to inspect blob: \(String(cString: strerror(errno)))"
        )
    }
    guard (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
        throw HelperError(domain: "helper", status: -1, message: "key blob is not a regular file")
    }
    let permissions = info.st_mode & mode_t(0o777)
    guard permissions == mode_t(0o600) else {
        throw HelperError(
            domain: "helper",
            status: -1,
            message: "key blob must be mode 0600 (got \(String(permissions, radix: 8)))"
        )
    }

    do {
        return try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() ?? Data()
    } catch {
        throw HelperError(domain: "helper", status: -1, message: "failed to read blob: \(error.localizedDescription)")
    }
}

// MARK: - Access control

func makeAccessControl(biometry: Bool) throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if biometry {
        // Biometry-preferred with a device-passcode fallback:
        // `.biometryCurrentSet` keeps the "key is invalidated when the
        // enrolled fingerprint set changes" defense (an attacker who enrolls
        // their own finger cannot use the key), while `.or, .devicePasscode`
        // lets the user fall back to the Mac password when Touch ID is
        // unavailable, flaky, or locked out — without it, a biometry lockout
        // makes the wrapping key permanently unusable until a screen unlock.
        flags.insert(.biometryCurrentSet)
        flags.insert(.or)
        flags.insert(.devicePasscode)
    }
    var acErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        flags,
        &acErr
    ) else {
        let message: String
        if let cf = acErr?.takeRetainedValue() {
            message = (cf as Error).localizedDescription
        } else {
            message = "SecAccessControlCreateWithFlags failed"
        }
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: message)
    }
    return access
}

// MARK: - Operations

func loadKey(tagHex: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    let blob = try readBlob(tagHex: tagHex)
    do {
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "failed to load enclave key: \(error.localizedDescription)")
    }
}

func generate(tagHex: String, unattended: Bool) throws -> Data {
    // One helper process is spawned per request, so an in-process mutex cannot
    // close the fileExists→write race. Hold a store-wide advisory file lock
    // across the complete duplicate check, Enclave generation, and atomic
    // publication. Concurrent generate requests for the same tag serialize;
    // the loser observes the winner's blob and returns duplicate-item without
    // replacing it.
    return try withStoreLock {
        if try pathExistsNoFollow(blobURL(tagHex: tagHex)) {
            throw HelperError(domain: "OSStatus", status: errDuplicateItem, message: "key already exists for tag")
        }
        // unattended → .privateKeyUsage only (no prompt); otherwise biometry-gated.
        let access = try makeAccessControl(biometry: !unattended)
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        } catch {
            throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "SecureEnclave key generation failed: \(error.localizedDescription)")
        }
        try writeBlob(key.dataRepresentation, tagHex: tagHex)
        return key.publicKey.x963Representation
    }
}

func publicKey(tagHex: String) throws -> Data {
    try loadKey(tagHex: tagHex).publicKey.x963Representation
}

func pathExistsNoFollow(_ url: URL) throws -> Bool {
    var info = stat()
    let result = url.path.withCString { lstat($0, &info) }
    if result == 0 {
        return true
    }
    if errno == ENOENT {
        return false
    }
    throw HelperError(
        domain: "helper",
        status: -1,
        message: "failed to inspect blob path: \(String(cString: strerror(errno)))"
    )
}

func deleteKey(tagHex: String) throws {
    let initialURL = blobURL(tagHex: tagHex)
    // Preserve idempotent no-op semantics without creating a store + lock when
    // no directory entry exists. lstat is intentional: a dangling final
    // symlink is still an entry and must be unlinked, or it permanently makes
    // no-replace generation return EEXIST.
    guard try pathExistsNoFollow(initialURL) else { return }
    try withStoreLock {
        let url = blobURL(tagHex: tagHex)
        let result = url.path.withCString { unlink($0) }
        if result != 0 {
            if errno == ENOENT {
                return
            }
            throw HelperError(
                domain: "helper",
                status: -1,
                message: "failed to delete blob: \(String(cString: strerror(errno)))"
            )
        }
        // The deletion is not crash-durable until its directory entry is
        // flushed. Do not claim reset success while the key name can return
        // after power loss.
        try syncStoreDirectory()
    }
}

func ecdh(tagHex: String, peerPub: Data) throws -> Data {
    let key = try loadKey(tagHex: tagHex)
    let peer: P256.KeyAgreement.PublicKey
    do {
        peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPub)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "invalid peer public key: \(error.localizedDescription)")
    }
    let shared: SharedSecret
    do {
        // This is the authorization boundary — triggers the Touch ID /
        // passcode prompt because the key carries .biometryCurrentSet.
        shared = try key.sharedSecretFromKeyAgreement(with: peer)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "key agreement failed: \(error.localizedDescription)")
    }
    // Raw 32-byte X coordinate — identical to SecKeyCopyKeyExchangeResult
    // (.ecdhKeyExchangeStandard) and the software fallback, so wrap.py's HKDF
    // input is unchanged.
    return shared.withUnsafeBytes { Data($0) }
}

func probe() throws {
    guard SecureEnclave.isAvailable else {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "Secure Enclave not available")
    }
    // Generate a throwaway .privateKeyUsage-only key (no biometry → no prompt)
    // and never persist it. Success proves the hardware path works.
    let access = try makeAccessControl(biometry: false)
    do {
        _ = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    } catch {
        throw HelperError(domain: "OSStatus", status: errAuthFailed, message: "probe key generation failed: \(error.localizedDescription)")
    }
}

// MARK: - Vault anchor items (login keychain, owned by this binary)

let anchorServiceBase = "mordred-hermes.vault.anchor.sekey"
let anchorMaxValueBytes = 4096
let anchorMaxAccountBytes = 128

// MORDRED_SEKEY_ANCHOR_NAMESPACE (live tests only) appends ".<namespace>" to the
// fixed service so a test never touches a real vault's anchor. It can only
// narrow the helper to another Mordred-prefixed service, never widen it.
func anchorService() throws -> String {
    let env = ProcessInfo.processInfo.environment
    guard let namespace = env["MORDRED_SEKEY_ANCHOR_NAMESPACE"], !namespace.isEmpty else {
        return anchorServiceBase
    }
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-")
    guard namespace.utf8.count <= 32, namespace.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
        throw HelperError(domain: "helper", status: -1, message: "invalid MORDRED_SEKEY_ANCHOR_NAMESPACE")
    }
    return anchorServiceBase + "." + namespace
}

func requireAccount(_ req: Request) -> String {
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    guard let account = req.account, !account.isEmpty, account.utf8.count <= anchorMaxAccountBytes,
          account.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
        fail("missing or invalid account")
    }
    return account
}

func requireAnchorValue(_ req: Request) -> Data {
    guard let hex = req.value_hex, let value = hexDecode(hex), !value.isEmpty, value.count <= anchorMaxValueBytes else {
        fail("missing or invalid value_hex")
    }
    return value
}

func keychainError(_ status: OSStatus, _ what: String) -> HelperError {
    let detail = (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
    return HelperError(domain: "OSStatus", status: Int(status), message: "\(what): \(detail)")
}

// The legacy (file-based) login keychain, like the former in-process Python
// path: the data-protection keychain would need the keychain-access-groups
// entitlement, which an ad-hoc-signed binary cannot carry.
func anchorQuery(account: String) throws -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: try anchorService(),
        kSecAttrAccount as String: account,
    ]
}

func anchorGet(account: String) throws -> Data {
    var query = try anchorQuery(account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        throw HelperError(domain: "OSStatus", status: errItemNotFound, message: "no anchor item")
    }
    guard status == errSecSuccess else {
        throw keychainError(status, "SecItemCopyMatching failed")
    }
    guard let data = result as? Data else {
        // Success without data would read as a present-but-empty anchor.
        throw HelperError(domain: "helper", status: -1, message: "SecItemCopyMatching returned no data")
    }
    return data
}

func anchorAdd(account: String, value: Data) throws -> OSStatus {
    var attrs = try anchorQuery(account: account)
    attrs[kSecValueData as String] = value
    // ThisDeviceOnly: never synced or migrated to another device; the anchor's
    // whole point is a pin that an imaged / stolen disk cannot carry along.
    attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    attrs[kSecAttrLabel as String] = "Mordred vault anchor"
    return SecItemAdd(attrs as CFDictionary, nil)
}

// Add only: a duplicate is reported, never overwritten (used by migration, so
// a concurrent writer's newer pin cannot be rolled back).
func anchorAddOnly(account: String, value: Data) throws {
    let status = try anchorAdd(account: account, value: value)
    if status == errSecDuplicateItem {
        throw HelperError(domain: "OSStatus", status: errDuplicateItem, message: "anchor item already exists")
    }
    guard status == errSecSuccess else {
        throw keychainError(status, "SecItemAdd failed")
    }
}

func anchorUpdate(account: String, value: Data) throws -> OSStatus {
    // Re-assert ThisDeviceOnly on every update so it can never be inherited as
    // something weaker from an older item.
    let update: [String: Any] = [
        kSecValueData as String: value,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    return SecItemUpdate(try anchorQuery(account: account) as CFDictionary, update as CFDictionary)
}

// Upsert, update first: every vault commit rewrites an anchor that already
// exists, so that is one keychain access; only a vault's first pin falls
// through to the add (and a lost add race updates the winner's item).
func anchorSet(account: String, value: Data) throws {
    let updated = try anchorUpdate(account: account, value: value)
    if updated == errSecSuccess {
        return
    }
    guard updated == errSecItemNotFound else {
        throw keychainError(updated, "SecItemUpdate failed")
    }
    let added = try anchorAdd(account: account, value: value)
    if added == errSecSuccess {
        return
    }
    guard added == errSecDuplicateItem else {
        throw keychainError(added, "SecItemAdd failed")
    }
    let retried = try anchorUpdate(account: account, value: value)
    guard retried == errSecSuccess else {
        throw keychainError(retried, "SecItemUpdate failed")
    }
}

func anchorDelete(account: String) throws {
    let status = SecItemDelete(try anchorQuery(account: account) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw keychainError(status, "SecItemDelete failed")
    }
}

// MARK: - Output

func emit(_ obj: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: obj) else {
        FileHandle.standardOutput.write("{\"error\":{\"domain\":\"helper\",\"status\":-1,\"message\":\"failed to serialize response\"}}".data(using: .utf8)!)
        exit(1)
    }
    FileHandle.standardOutput.write(data)
}

func emitError(_ e: HelperError) -> Never {
    emit(["error": ["domain": e.domain, "status": e.status, "message": e.message]])
    exit(1)
}

func fail(_ message: String) -> Never {
    emitError(HelperError(domain: "helper", status: -1, message: message))
}

// MARK: - Main

let input = FileHandle.standardInput.readDataToEndOfFile()
guard let request = try? JSONDecoder().decode(Request.self, from: input) else {
    fail("invalid JSON request on stdin")
}

func requireTagHex(_ req: Request) -> String {
    guard let hex = req.tag_hex, hexDecode(hex) != nil else {
        fail("missing or invalid tag_hex")
    }
    return hex
}

do {
    switch request.cmd {
    case "generate":
        emit(["public_key_hex": hexEncode(try generate(tagHex: requireTagHex(request), unattended: request.unattended ?? false))])
    case "public_key":
        emit(["public_key_hex": hexEncode(try publicKey(tagHex: requireTagHex(request)))])
    case "delete":
        try deleteKey(tagHex: requireTagHex(request))
        emit(["ok": true])
    case "ecdh":
        guard let peerHex = request.peer_pub_hex, let peer = hexDecode(peerHex) else {
            fail("missing or invalid peer_pub_hex")
        }
        emit(["shared_hex": hexEncode(try ecdh(tagHex: requireTagHex(request), peerPub: peer))])
    case "probe":
        try probe()
        emit(["ok": true])
    case "anchor_get":
        emit(["value_hex": hexEncode(try anchorGet(account: requireAccount(request)))])
    case "anchor_add":
        try anchorAddOnly(account: requireAccount(request), value: requireAnchorValue(request))
        emit(["ok": true])
    case "anchor_set":
        try anchorSet(account: requireAccount(request), value: requireAnchorValue(request))
        emit(["ok": true])
    case "anchor_delete":
        try anchorDelete(account: requireAccount(request))
        emit(["ok": true])
    default:
        fail("unknown cmd: \(request.cmd)")
    }
} catch let e as HelperError {
    emitError(e)
} catch {
    fail("unexpected error: \(error.localizedDescription)")
}
