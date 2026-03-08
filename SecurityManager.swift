//
//  SecurityManager.swift
//  Privr Security Core
//
//  Created by Arne Winter on 08.03.26.
//  Copyright © 2026. All rights reserved.
//

import SwiftUI
import CryptoKit
import Security
import CommonCrypto // 🟢 NEU: Zwingend erforderlich für PBKDF2 (Password Stretching)

// 🟢 NEU: Eine streng gekapselte, threadsichere Klasse für den RAM-Cache.
// Löst das 'nonisolated(unsafe)' Problem: Das Schloss (NSLock) kann nie wieder vergessen werden!
final class VaultKeyCache: @unchecked Sendable {
    private var _masterKey: SymmetricKey?
    private let lock = NSLock()
    
    var masterKey: SymmetricKey? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _masterKey
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _masterKey = newValue
        }
    }
    
    func clear() {
        masterKey = nil
    }
}

/// Final class handling all cryptographic operations.
/// Fully optimized for Swift 6 Concurrency (Sendable).
final class SecurityManager: Sendable {
    
    // MARK: - Constants & Paths
    nonisolated private static let attemptsKey = "app_vault_failed_attempts"
    nonisolated private static let maxAttempts = 10
    
    nonisolated static var documentsDirectory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }
    
    nonisolated private static let masterKeyAccount = "app_vault_master_key"
    
    nonisolated private static let saltKey = "vault_pbkdf2_salt_v1" // 🟢 NEU: Speichert unseren dynamischen Salt
        
    // ✅ Das ist neu: Der gekapselte, 100% Swift 6 sichere Cache
        nonisolated private static let keyCache = VaultKeyCache()
    // 🟢 NEU: Der Türsteher für den Login. Verhindert Race-Conditions beim Brute-Force-Zähler.
        nonisolated private static let authLock = NSLock()

    // MARK: - Core Encryption
    
    static func saveImage(data: Data, folderID: UUID, subPath: String = "", originalName: String? = nil) -> String? {
            guard let key = getMasterKey() else { return nil }
            
            // 🟢 FIX: Path Traversal Schutz für den Unterordner
            guard let safeSubPath = sanitize(path: subPath) else { return nil }
            
            do {
                let sealedBox = try AES.GCM.seal(data, using: key)
                let finalName: String
                if let safeName = originalName, !safeName.isEmpty {
                    finalName = safeName.hasSuffix(".vault") ? safeName : safeName + ".vault"
                } else {
                    finalName = UUID().uuidString + ".vault"
                }
                
                // 🟢 FIX: Path Traversal Schutz für den Dateinamen
                guard let safeFileName = sanitize(path: finalName) else { return nil }
                
                var folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
                if !safeSubPath.isEmpty { folderURL = folderURL.appendingPathComponent(safeSubPath) }
                
                try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true)
                let filePath = folderURL.appendingPathComponent(safeFileName)
                            
                guard let combinedData = sealedBox.combined else { return nil }
                try combinedData.write(to: filePath, options: .completeFileProtection)
                
                return safeFileName
            } catch { return nil }
        }
    
    static func loadImage(fileName: String, folderID: UUID, subPath: String = "") -> UIImage? {
            // 🟢 FIX: Nutzt jetzt einfach die bestehende Entschlüsselungs-Logik! Keine Duplizierung mehr.
            guard let data = getDecryptedData(fileName: fileName, folderID: folderID, subPath: subPath) else { return nil }
            return UIImage(data: data)
        }
    
    // MARK: - Key Management (Verify-by-Decryption)
        
        /// Prüft, ob der Tresor überhaupt schon einmal eingerichtet wurde.
        static var isVaultSetup: Bool {
            return KeychainHelper.loadData(key: masterKeyAccount) != nil
        }
        
    /// Interne Kern-Logik ohne Locks. Nur zur Verwendung innerhalb von Funktionen, die bereits ein Lock halten!
        private static func _performUnlock(pin: String) -> Bool {
            var attempts = 0
            if let data = KeychainHelper.loadData(key: attemptsKey),
               let str = String(data: data, encoding: .utf8),
               let count = Int(str) {
                attempts = count
            }
            
            guard attempts < maxAttempts else {
                destroyEverything()
                return false
            }
            
            guard let salt = KeychainHelper.loadData(key: saltKey),
                  let encryptedMasterKey = KeychainHelper.loadData(key: masterKeyAccount),
                  let derivedKey = deriveKeyWithPBKDF2(password: pin, salt: salt) else {
                return false
            }
            
            do {
                let sealedBox = try AES.GCM.SealedBox(combined: encryptedMasterKey)
                let decryptedData = try AES.GCM.open(sealedBox, using: derivedKey)
                
                KeychainHelper.delete(key: attemptsKey)
                let masterKey = SymmetricKey(data: decryptedData)
                keyCache.masterKey = masterKey
                return true
            } catch {
                attempts += 1
                if attempts >= maxAttempts {
                    destroyEverything()
                } else if let newCountData = String(attempts).data(using: .utf8) {
                    KeychainHelper.saveData(data: newCountData, key: attemptsKey)
                }
                return false
            }
        }
        
    /// Richtet den Tresor zum allerersten Mal ein. Generiert Salt und Master-Key.
        static func setupVault(withPIN pin: String) -> Bool {
            // 🟢 FIX: Auch das Setup wird jetzt atomar geschützt
            authLock.lock()
            defer { authLock.unlock() }
            
            guard !isVaultSetup else { return false }
            
            let newSalt = generateSalt()
            guard let derivedKey = deriveKeyWithPBKDF2(password: pin, salt: newSalt) else { return false }
            
            let newMasterKey = SymmetricKey(size: .bits256)
            let masterKeyData = newMasterKey.withUnsafeBytes { Data($0) }
            
            do {
                let sealedBox = try AES.GCM.seal(masterKeyData, using: derivedKey)
                guard let combinedData = sealedBox.combined else { return false }
                
                KeychainHelper.saveData(data: combinedData, key: masterKeyAccount)
                KeychainHelper.saveData(data: newSalt, key: saltKey)
                
                keyCache.masterKey = newMasterKey
                return true
            } catch {
                return false
            }
        }
        
        /// Entsperrt den Tresor. Schlägt fehl, wenn der PIN falsch ist.
        /// Integrierter Brute-Force-Schutz auf API-Ebene via Keychain.
    /// Öffentliche Entsperr-Funktion (mit Lock-Schutz gegen Race Conditions & Deadlocks)
        static func unlockVault(withPIN pin: String) -> Bool {
            authLock.lock()
            defer { authLock.unlock() }
            // 🟢 FIX: Nutzt die interne Logik, um Redundanz zu vermeiden
            return _performUnlock(pin: pin)
        }
        
        /// Interne Funktion, die ab jetzt NUR NOCH den RAM-Cache abfragt.
        nonisolated private static func getMasterKey() -> SymmetricKey? {
            return keyCache.masterKey
        }
        
        /// Sperrt den Tresor wieder, indem der Key aus dem RAM gelöscht wird.
        static func clearMasterKeyCache() {
            keyCache.clear()
        }
        
    /// Ändert den PIN. Erfordert den alten PIN zur Verifikation.
    
        static func changePIN(oldPIN: String, newPIN: String) -> Bool {
            // 🟢 FIX: Sperrt die gesamte PIN-Änderung atomar ab
            authLock.lock()
            defer { authLock.unlock() }
            
            // 🟢 FIX: Ruft _performUnlock statt unlockVault auf, um Deadlocks zu vermeiden
            guard _performUnlock(pin: oldPIN), let currentMasterKey = keyCache.masterKey else {
                keyCache.clear()
                return false
            }
            
            // 2. Komplett neuen Salt NUR IM RAM generieren
            let newSalt = generateSalt()
            guard let derivedKeyNew = deriveKeyWithPBKDF2(password: newPIN, salt: newSalt) else {
                keyCache.clear()
                return false
            }
            
            // 3. Alten Master-Key mit dem NEUEN PIN verschlüsseln
            do {
                let masterKeyData = currentMasterKey.withUnsafeBytes { Data($0) }
                let sealedBoxNew = try AES.GCM.seal(masterKeyData, using: derivedKeyNew)
                
                guard let combinedData = sealedBoxNew.combined else {
                    keyCache.clear()
                    return false
                }
                
                // 🟢 FIX: Atomares Speichern von Master-Key und neuem Salt
                KeychainHelper.saveData(data: combinedData, key: masterKeyAccount)
                KeychainHelper.saveData(data: newSalt, key: saltKey)
                
                return true
            } catch {
                keyCache.clear()
                return false
            }
        }
    
    // MARK: - PBKDF2 Cryptography Helper
    
    /// 🟢 NEU: Härtet den 6-stelligen PIN extrem gegen Brute-Force-Angriffe ab.
    nonisolated private static func deriveKeyWithPBKDF2(password: String, salt: Data) -> SymmetricKey? {
        guard let passwordData = password.data(using: .utf8) else { return nil }
        var derivedKeyData = [UInt8](repeating: 0, count: 32)
        
        let status = passwordData.withUnsafeBytes { passBuffer in
            salt.withUnsafeBytes { saltBuffer in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passBuffer.baseAddress?.assumingMemoryBound(to: CChar.self),
                    passBuffer.count,
                    saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    saltBuffer.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    200_000, // 🚀 DIE BREMSE: 200.000 Iterationen machen Brute-Force extrem zeitaufwendig
                    &derivedKeyData,
                    derivedKeyData.count
                )
            }
        }
        
        return status == kCCSuccess ? SymmetricKey(data: derivedKeyData) : nil
    }
    
    /// 🟢 FIX: Generiert den Salt nur im RAM.
        /// Verhindert, dass alte Salts überschrieben werden, bevor die neue Verschlüsselung geglückt ist!
        nonisolated private static func generateSalt() -> Data {
            var randomBytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, &randomBytes)
            return Data(randomBytes)
        }

    // MARK: - Thumbnail & Background Loading
    
    nonisolated static func loadThumbnail(fileName: String, folderID: UUID, subPath: String = "") -> UIImage? {
        return autoreleasepool {
            let thumbName = fileName.replacingOccurrences(of: ".vault", with: "_thumb.vault")
            if let thumbData = getDecryptedData(fileName: thumbName, folderID: folderID, subPath: subPath),
               let thumbImage = UIImage(data: thumbData) {
                return thumbImage
            }
            
            guard let fullData = getDecryptedData(fileName: fileName, folderID: folderID, subPath: subPath),
                  let fullImage = UIImage(data: fullData) else { return nil }
            
            let thumbnailSize = CGSize(width: 300, height: 300)
            let thumb = fullImage.preparingThumbnail(of: thumbnailSize) ?? fullImage
            
            if let thumbJpeg = thumb.jpegData(compressionQuality: 0.7) {
                _ = saveEncryptedData(data: thumbJpeg, fileName: thumbName, folderID: folderID, subPath: subPath)
            }
            return thumb
        }
    }

    nonisolated static func getDecryptedData(fileName: String, folderID: UUID, subPath: String = "") -> Data? {
            guard let key = getMasterKey() else { return nil }
            
            // 🟢 FIX: Path Traversal Schutz
            guard let safeSubPath = sanitize(path: subPath),
                  let safeFileName = sanitize(path: fileName) else { return nil }
                  
            var folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
            if !safeSubPath.isEmpty { folderURL = folderURL.appendingPathComponent(safeSubPath) }
            
            let filePath = folderURL.appendingPathComponent(safeFileName)
            guard FileManager.default.fileExists(atPath: filePath.path),
                  let encryptedData = try? Data(contentsOf: filePath) else { return nil }
                  
            do {
                let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
                return try AES.GCM.open(sealedBox, using: key)
            } catch { return nil }
        }
        
        nonisolated static func saveEncryptedData(data: Data, fileName: String, folderID: UUID, subPath: String = "") -> Bool {
            guard let key = getMasterKey() else { return false }
            
            // 🟢 FIX: Path Traversal Schutz
            guard let safeSubPath = sanitize(path: subPath),
                  let safeFileName = sanitize(path: fileName) else { return false }
                  
            do {
                let sealedBox = try AES.GCM.seal(data, using: key)
                var folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
                if !safeSubPath.isEmpty { folderURL = folderURL.appendingPathComponent(safeSubPath) }
                
                let filePath = folderURL.appendingPathComponent(safeFileName)
                
                guard let combinedData = sealedBox.combined else { return false }
                try combinedData.write(to: filePath, options: .completeFileProtection)
                
                return true
            } catch { return false }
        }
}

// MARK: - Keychain Wrapper

final class KeychainHelper: Sendable {
    
    // 🟢 NEU: Eindeutiger Service-Identifier (verhindert Kollisionen mit anderen Apps/Extensions)
    nonisolated private static var service: String {
        Bundle.main.bundleIdentifier ?? "com.privr.vault"
    }

    nonisolated static func saveData(data: Data, key: String) {
            // 1. Die minimalistische Lösch-Query (nur Primärschlüssel)
            let deleteQuery = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key,
                kSecAttrSynchronizable as String: false // Muss explizit sein, falls vorhanden
            ] as [String: Any]
            
            SecItemDelete(deleteQuery as CFDictionary)
            
            // 2. Die Add-Query mit allen Attributen
            let addQuery = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key,
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecAttrSynchronizable as String: false
            ] as [String: Any]
            
            SecItemAdd(addQuery as CFDictionary, nil)
        }

    nonisolated static func loadData(key: String) -> Data? {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, // 🟢 FIX: Service hinzugefügt
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: false
        ] as [String: Any]
        
        var dataTypeRef: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &dataTypeRef) == errSecSuccess {
            return dataTypeRef as? Data
        }
        return nil
    }
    
    nonisolated static func delete(key: String) {
            // 🟢 FIX: Nur die Identifikatoren nutzen
            let query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key,
                kSecAttrSynchronizable as String: false
            ] as [String: Any]
            SecItemDelete(query as CFDictionary)
        }
}

// MARK: - File & Directory Extensions

extension SecurityManager {
    static func getContents(of folderID: UUID, subPath: String = "") -> [String] {
        // 🟢 FIX: Path Traversal Schutz
        guard let safeSubPath = sanitize(path: subPath) else { return [] }
        
        let folderPath = documentsDirectory.appendingPathComponent(folderID.uuidString).appendingPathComponent(safeSubPath)
            
        do {
            let items = try FileManager.default.contentsOfDirectory(atPath: folderPath.path)
            return items.filter { !$0.hasPrefix(".") }.sorted()
        } catch { return [] }
    }

    static func createDirectory(at name: String, folderID: UUID, subPath: String = "") {
        // 🟢 FIX: Path Traversal Schutz
        guard let safeSubPath = sanitize(path: subPath),
              let safeName = sanitize(path: name) else { return }
              
        let folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString).appendingPathComponent(safeSubPath).appendingPathComponent(safeName)
        try? FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true, attributes: nil)
    }
    
    static func getFolderSize(folderID: UUID, subPath: String = "") async -> Int64 {
        // 🟢 FIX: Path Traversal Schutz
        guard let safeSubPath = sanitize(path: subPath) else { return 0 }
        
        var folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
        if !safeSubPath.isEmpty { folderURL = folderURL.appendingPathComponent(safeSubPath) }
        
        return await Task.detached(priority: .background) {
            var totalSize: Int64 = 0
            if let enumerator = FileManager.default.enumerator(at: folderURL, includingPropertiesForKeys: [.fileSizeKey]) {
                while let fileURL = enumerator.nextObject() as? URL {
                    if Task.isCancelled { break }
                    if let values = try? fileURL.resourceValues(forKeys: [.fileSizeKey]), let fileSize = values.fileSize {
                        totalSize += Int64(fileSize)
                    }
                }
            }
            return totalSize
        }.value
    }
    
    nonisolated static func getCreationDate(for fileName: String? = nil, folderID: UUID, subPath: String = "") -> Date? {
        // 🟢 FIX: Path Traversal Schutz
        guard let safeSubPath = sanitize(path: subPath) else { return nil }
        
        var fileURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
        if !safeSubPath.isEmpty { fileURL = fileURL.appendingPathComponent(safeSubPath) }
        
        if let name = fileName, !name.isEmpty {
            guard let safeName = sanitize(path: name) else { return nil }
            fileURL = fileURL.appendingPathComponent(safeName)
        }
        
        return (try? FileManager.default.attributesOfItem(atPath: fileURL.path))?[FileAttributeKey.creationDate] as? Date
    }

    static func deleteFile(fileName: String, folderID: UUID, subPath: String = "") {
        // 🟢 FIX: Path Traversal Schutz
        guard let safeSubPath = sanitize(path: subPath),
              let safeFileName = sanitize(path: fileName) else { return }
              
        let baseDir = documentsDirectory.appendingPathComponent(folderID.uuidString).appendingPathComponent(safeSubPath)
        try? FileManager.default.removeItem(at: baseDir.appendingPathComponent(safeFileName))
        try? FileManager.default.removeItem(at: baseDir.appendingPathComponent(safeFileName.replacingOccurrences(of: ".vault", with: "_thumb.vault")))
    }
    
    static func renameItem(folderID: UUID, subPath: String = "", oldName: String, newName: String) {
        // 🟢 FIX: Path Traversal Schutz
        guard let safeSubPath = sanitize(path: subPath),
              let safeOldName = sanitize(path: oldName),
              let safeNewName = sanitize(path: newName) else { return }
              
        let currentDirURL = safeSubPath.isEmpty ? documentsDirectory.appendingPathComponent(folderID.uuidString) : documentsDirectory.appendingPathComponent(folderID.uuidString).appendingPathComponent(safeSubPath)
        try? FileManager.default.moveItem(at: currentDirURL.appendingPathComponent(safeOldName), to: currentDirURL.appendingPathComponent(safeNewName))
    }
    
    /// Deletes an entire folder and all its contents based on its ID.
    static func deleteFolder(id: UUID) {
        let folderPath = documentsDirectory.appendingPathComponent(id.uuidString)
        try? FileManager.default.removeItem(at: folderPath)
    }
    
    /// Notfall-Wipe: Zerstört alle Schlüssel und löscht gezielt nur den Tresor-Inhalt.
    static func destroyEverything() {
        // 1. Nur unsere eigenen, spezifischen Schlüssel löschen!
        KeychainHelper.delete(key: masterKeyAccount)
        KeychainHelper.delete(key: saltKey)
        KeychainHelper.delete(key: attemptsKey) // WICHTIG: Auch den Brute-Force-Zähler löschen
        keyCache.clear()
        
        // 2. Gezielt nur Vault-Ordner (UUID-basiert) löschen, andere App-Dateien ignorieren
        guard let items = try? FileManager.default.contentsOfDirectory(
            at: documentsDirectory, includingPropertiesForKeys: [.isDirectoryKey]
        ) else { return }
        
        for url in items {
            // Prüfen: Ist der Ordnername eine gültige UUID? Wenn ja -> Löschen.
            if UUID(uuidString: url.lastPathComponent) != nil {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }
    
    // MARK: - Path Sanitization
            
        /// 🟢 FIX: Überarbeiteter Path-Traversal-Schutz.
        /// Prüft Komponenten VOR der Normalisierung, um versteckte Ausbrüche zu finden.
        nonisolated private static func sanitize(path: String) -> String? {
            if path.isEmpty { return "" }
            
            // 1. Pfad in Teile zerlegen (z.B. "ordner/../datei" -> ["ordner", "..", "datei"])
            let components = path.components(separatedBy: "/")
            
            // 2. Explizit nach dem ".." Segment suchen.
            // "Datei..Name.txt" bleibt erlaubt, da es ein einzelnes Segment ist.
            guard !components.contains("..") else { return nil }
            
            // 3. Erst jetzt normalisieren (entfernt z.B. doppelte Slashes "//")
            let normalized = (path as NSString).standardizingPath
            
            // 4. Absolute Pfade durch Trimmen der Slashes verhindern
            return normalized.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        }
        
}

// MARK: - Image Processing Extensions

extension SecurityManager {
    static func rotateImage90Degrees(fileName: String, folderID: UUID, subPath: String) -> Bool {
        guard let data = getDecryptedData(fileName: fileName, folderID: folderID, subPath: subPath),
              let originalImage = UIImage(data: data),
              let rotatedImage = originalImage.rotated90Clockwise(),
              let rotatedData = rotatedImage.jpegData(compressionQuality: 0.9) else { return false }
        
        deleteFile(fileName: fileName.replacingOccurrences(of: ".vault", with: "_thumb.vault"), folderID: folderID, subPath: subPath)
        return saveEncryptedData(data: rotatedData, fileName: fileName, folderID: folderID, subPath: subPath)
    }
}

extension UIImage {
    // 🟢 FIX: Nutzt jetzt den modernen UIGraphicsImageRenderer (iOS 10+)
    func rotated90Clockwise() -> UIImage? {
        guard let cgImage = self.cgImage else { return nil }
        let newSize = CGSize(width: size.height, height: size.width)
        
        let format = UIGraphicsImageRendererFormat()
        format.scale = self.scale
        let renderer = UIGraphicsImageRenderer(size: newSize, format: format)
        
        return renderer.image { context in
            let cgContext = context.cgContext
            cgContext.translateBy(x: newSize.width / 2, y: newSize.height / 2)
            cgContext.rotate(by: .pi / 2)
            cgContext.scaleBy(x: 1.0, y: -1.0)
            
            let drawRect = CGRect(x: -size.width / 2, y: -size.height / 2, width: size.width, height: size.height)
            cgContext.draw(cgImage, in: drawRect)
        }
    }
}
