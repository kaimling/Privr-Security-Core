//
//  SecurityManager.swift
//  Privr Security Core
//
//  Created by Arne Winter on 21.02.26.
//  Copyright © 2026. All rights reserved.
//
//  Description:
//  Central security module for the Privr Photo Vault app.
//  Handles AES-256-GCM encryption, HKDF key derivation,
//  and secure key management via the iOS Keychain.
//

import SwiftUI
import CryptoKit
import Security

/// Final class handling all cryptographic operations.
/// Fully optimized for Swift 6 Concurrency (Sendable).
final class SecurityManager: Sendable {
    
    // MARK: - Constants & Paths
    
    /// Securely retrieves the Documents Directory of the app container.
    nonisolated static var documentsDirectory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }
    
    nonisolated private static let masterKeyAccount = "app_vault_master_key"
    nonisolated private static let passwordKey = "vault_pin_v1"

    // MARK: - Core Encryption
    
    /// Encrypts image data and saves it to the vault.
    /// - Parameters:
    ///   - data: The raw image data to be encrypted.
    ///   - folderID: UUID of the target folder.
    ///   - subPath: Optional subpath within the folder.
    ///   - originalName: The original filename to preserve.
    /// - Returns: The encrypted filename (.vault) on success.
    static func saveImage(data: Data, folderID: UUID, subPath: String = "", originalName: String? = nil) -> String? {
        guard let key = getMasterKey() else {
            #if DEBUG
            print("SECURITY ERROR: No MasterKey available.")
            #endif
            return nil
        }
        
        do {
            // AES-GCM is used to ensure both confidentiality and authenticity (AEAD).
            let sealedBox = try AES.GCM.seal(data, using: key)
            
            let finalName: String
            if let safeName = originalName, !safeName.isEmpty {
                finalName = safeName.hasSuffix(".vault") ? safeName : safeName + ".vault"
            } else {
                finalName = UUID().uuidString + ".vault"
            }
            
            var folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
            if !subPath.isEmpty {
                folderURL = folderURL.appendingPathComponent(subPath)
            }
            
            try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true)
            
            let filePath = folderURL.appendingPathComponent(finalName)
            // Writing with complete file protection enabled.
            try sealedBox.combined!.write(to: filePath, options: .completeFileProtection)
            
            return finalName
        } catch {
            #if DEBUG
            print("Encryption Error: \(error)")
            #endif
            return nil
        }
    }
    
    /// Decrypts an image for full-screen display.
    static func loadImage(fileName: String, folderID: UUID, subPath: String = "") -> UIImage? {
        let filePath = documentsDirectory
            .appendingPathComponent(folderID.uuidString)
            .appendingPathComponent(subPath)
            .appendingPathComponent(fileName)
        
        guard let encryptedData = try? Data(contentsOf: filePath),
              let key = getMasterKey() else { return nil }
        
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
            let decryptedData = try AES.GCM.open(sealedBox, using: key)
            return UIImage(data: decryptedData)
        } catch { return nil }
    }

    // MARK: - Key Management (Private)
    
    /// Retrieves or generates the Master Key from the Keychain.
    /// The Master Key is itself encrypted with a key derived from the user's PIN.
    nonisolated private static func getMasterKey() -> SymmetricKey? {
        guard let userPassword = KeychainHelper.load(key: passwordKey) else {
            return nil
        }
        
        let userPasswordData = Data(userPassword.utf8)
        
        // NOTE: In a production environment, the salt should ideally be unique per installation.
        // Here we use a static salt for HKDF derivation.
        let salt = "VaultSalt123".data(using: .utf8)!
        
        // Key derivation via HKDF (SHA256).
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: userPasswordData),
            salt: salt, 
            outputByteCount: 32
        )

        if let encryptedMasterKey = KeychainHelper.loadData(key: masterKeyAccount) {
            do {
                let sealedBox = try AES.GCM.SealedBox(combined: encryptedMasterKey)
                let decryptedData = try AES.GCM.open(sealedBox, using: derivedKey)
                return SymmetricKey(data: decryptedData)
            } catch {
                #if DEBUG
                print("CRITICAL: MasterKey found but could not be decrypted!")
                #endif
                return nil
            }
        } else {
            // Initialization: Generate new Master Key (AES-256).
            let newMasterKey = SymmetricKey(size: .bits256)
            let masterKeyData = newMasterKey.withUnsafeBytes { Data($0) }
            do {
                let sealedBox = try AES.GCM.seal(masterKeyData, using: derivedKey)
                KeychainHelper.saveData(data: sealedBox.combined!, key: masterKeyAccount)
                return newMasterKey
            } catch {
                return nil
            }
        }
    }
    
    // MARK: - Thumbnail & Background Loading
    
    /// Loads or generates an encrypted thumbnail.
    /// Uses autoreleasepool to prevent memory spikes during mass decryption.
    nonisolated static func loadThumbnail(fileName: String, folderID: UUID, subPath: String = "") -> UIImage? {
        return autoreleasepool {
            let thumbName = fileName.replacingOccurrences(of: ".vault", with: "_thumb.vault")
            
            if let thumbData = getDecryptedData(fileName: thumbName, folderID: folderID, subPath: subPath),
               let thumbImage = UIImage(data: thumbData) {
                return thumbImage
            }
            
            guard let fullData = getDecryptedData(fileName: fileName, folderID: folderID, subPath: subPath),
                  let fullImage = UIImage(data: fullData) else {
                return nil
            }
            
            let thumbnailSize = CGSize(width: 300, height: 300)
            let thumb = fullImage.preparingThumbnail(of: thumbnailSize) ?? fullImage
            
            if let thumbJpeg = thumb.jpegData(compressionQuality: 0.7) {
                _ = saveEncryptedData(data: thumbJpeg, fileName: thumbName, folderID: folderID, subPath: subPath)
            }
            
            return thumb
        }
    }

    /// Helper function to decrypt binary data.
    nonisolated static func getDecryptedData(fileName: String, folderID: UUID, subPath: String = "") -> Data? {
        guard let key = getMasterKey() else { return nil }
        
        var folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
        if !subPath.isEmpty {
            folderURL = folderURL.appendingPathComponent(subPath)
        }
        let filePath = folderURL.appendingPathComponent(fileName)
        
        guard FileManager.default.fileExists(atPath: filePath.path) else { return nil }
        
        guard let encryptedData = try? Data(contentsOf: filePath) else { return nil }
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
            return try AES.GCM.open(sealedBox, using: key)
        } catch { return nil }
    }
    
    /// Helper function for direct encrypted storage (e.g., for rotation or thumbnails).
    nonisolated static func saveEncryptedData(data: Data, fileName: String, folderID: UUID, subPath: String = "") -> Bool {
        guard let key = getMasterKey() else { return false }
        
        do {
            let sealedBox = try AES.GCM.seal(data, using: key)
            
            var folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
            if !subPath.isEmpty {
                folderURL = folderURL.appendingPathComponent(subPath)
            }
            let filePath = folderURL.appendingPathComponent(fileName)
            
            try sealedBox.combined!.write(to: filePath, options: .completeFileProtection)
            return true
        } catch { return false }
    }
}

// MARK: - Keychain Wrapper

/// Final class for secure access to the iOS Keychain.
final class KeychainHelper: Sendable {
    
    nonisolated static func save(password: String, key: String) {
        let data = Data(password.utf8)
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ] as [String: Any]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
    
    nonisolated static func load(key: String) -> String? {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as [String: Any]
        
        var dataTypeRef: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &dataTypeRef) == errSecSuccess, let data = dataTypeRef as? Data {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }

    nonisolated static func saveData(data: Data, key: String) {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ] as [String: Any]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    nonisolated static func loadData(key: String) -> Data? {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as [String: Any]
        
        var dataTypeRef: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &dataTypeRef) == errSecSuccess { 
            return dataTypeRef as? Data 
        }
        return nil
    }
    
    nonisolated static func resetAll() {
        let secClasses = [
            kSecClassGenericPassword,
            kSecClassInternetPassword,
            kSecClassCertificate,
            kSecClassKey,
            kSecClassIdentity
        ]
        for secClass in secClasses {
            let query = [kSecClass as String: secClass] as CFDictionary
            SecItemDelete(query)
        }
    }
}

// MARK: - File & Directory Extensions

extension SecurityManager {
    
    /// Lists all encrypted files within a specific folder.
    static func getContents(of folderID: UUID, subPath: String = "") -> [String] {
        let cleanSubPath = subPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let folderPath = documentsDirectory
            .appendingPathComponent(folderID.uuidString)
            .appendingPathComponent(cleanSubPath)
            
        do {
            let items = try FileManager.default.contentsOfDirectory(atPath: folderPath.path)
            return items.filter { !$0.hasPrefix(".") }.sorted()
        } catch { return [] }
    }

    /// Creates a new directory within the encrypted vault.
    static func createDirectory(at name: String, folderID: UUID, subPath: String = "") {
        let folderURL = documentsDirectory
            .appendingPathComponent(folderID.uuidString)
            .appendingPathComponent(subPath)
            .appendingPathComponent(name)
        
        do {
            try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true, attributes: nil)
        } catch {
            #if DEBUG
            print("Error creating folder: \(error.localizedDescription)")
            #endif
        }
    }
    
    /// Calculates the total size of a directory asynchronously (Swift 6 compliant).
    static func getFolderSize(folderID: UUID, subPath: String = "") async -> Int64 {
        let cleanSubPath = subPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        var folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
        
        if !cleanSubPath.isEmpty {
            folderURL = folderURL.appendingPathComponent(cleanSubPath)
        }
        
        return await Task.detached(priority: .background) {
            var totalSize: Int64 = 0
            if let enumerator = FileManager.default.enumerator(at: folderURL, includingPropertiesForKeys: [.fileSizeKey]) {
                // Using while let for Swift 6 iterator compatibility.
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
    
    /// Retrieves the creation date of a file (nonisolated for background task usage).
    nonisolated static func getCreationDate(for fileName: String? = nil, folderID: UUID, subPath: String = "") -> Date? {
        var fileURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
        if !subPath.isEmpty { fileURL = fileURL.appendingPathComponent(subPath) }
        if let name = fileName, !name.isEmpty { fileURL = fileURL.appendingPathComponent(name) }
        
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
            return attributes[FileAttributeKey.creationDate] as? Date
        } catch { return nil }
    }

    /// Deletes a file and its associated secret thumbnail.
    static func deleteFile(fileName: String, folderID: UUID, subPath: String = "") {
        let baseDir = documentsDirectory.appendingPathComponent(folderID.uuidString).appendingPathComponent(subPath)
        let fileURL = baseDir.appendingPathComponent(fileName)
        let thumbName = fileName.replacingOccurrences(of: ".vault", with: "_thumb.vault")
        let thumbURL = baseDir.appendingPathComponent(thumbName)
        
        try? FileManager.default.removeItem(at: fileURL)
        try? FileManager.default.removeItem(at: thumbURL)
    }
    
    /// Renames an item within the file system.
    static func renameItem(folderID: UUID, subPath: String = "", oldName: String, newName: String) {
        let folderURL = documentsDirectory.appendingPathComponent(folderID.uuidString)
        let currentDirURL = subPath.isEmpty ? folderURL : folderURL.appendingPathComponent(subPath)
        
        let oldURL = currentDirURL.appendingPathComponent(oldName)
        let newURL = currentDirURL.appendingPathComponent(newName)
        
        try? FileManager.default.moveItem(at: oldURL, to: newURL)
    }
}

// MARK: - Image Processing Extensions

extension SecurityManager {
    
    /// Rotates an encrypted image by 90 degrees and updates both the file and thumbnail.
    static func rotateImage90Degrees(fileName: String, folderID: UUID, subPath: String) -> Bool {
        guard let data = getDecryptedData(fileName: fileName, folderID: folderID, subPath: subPath),
              let originalImage = UIImage(data: data),
              let rotatedImage = originalImage.rotated90Clockwise(),
              let rotatedData = rotatedImage.jpegData(compressionQuality: 0.9) else {
            return false
        }
        
        let thumbName = fileName.replacingOccurrences(of: ".vault", with: "_thumb.vault")
        deleteFile(fileName: thumbName, folderID: folderID, subPath: subPath)
        
        return saveEncryptedData(data: rotatedData, fileName: fileName, folderID: folderID, subPath: subPath)
    }
}

extension UIImage {
    /// Helper function for physical pixel rotation.
    func rotated90Clockwise() -> UIImage? {
        guard let cgImage = self.cgImage else { return nil }
        let newSize = CGSize(width: size.height, height: size.width)
        UIGraphicsBeginImageContextWithOptions(newSize, false, scale)
        guard let context = UIGraphicsGetCurrentContext() else { return nil }
        
        context.translateBy(x: newSize.width / 2, y: newSize.height / 2)
        context.rotate(by: .pi / 2)
        context.scaleBy(x: 1.0, y: -1.0)
        
        let drawRect = CGRect(x: -size.width / 2, y: -size.height / 2, width: size.width, height: size.height)
        context.draw(cgImage, in: drawRect)
        
        let rotatedImage = UIGraphicsGetImageFromCurrentImageContext()
        UIGraphicsEndImageContext()
        return rotatedImage
    }
}
