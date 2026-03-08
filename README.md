# 📑 Project: Privr Security Core
**Advanced Local Encryption Engine for iOS (Swift 6)**

This repository contains the cryptographic core of the Privr Vault. The architecture follows "Security by Design" principles to protect user data through hardware-bound encryption and industry-leading hardening against brute-force attacks.

---

## 🇺🇸 English Version

### 🛡️ Security Architecture
The engine implements a **Zero-Knowledge Architecture**. Neither the PIN nor the Master Key is ever stored in plain text.

* **Key Derivation (PBKDF2):** Uses 200,000 iterations of PBKDF2-SHA256 with a unique 32-byte salt to derive an intermediate key from the user's PIN. This significantly slows down local brute-force attempts.
* **Verify-by-Decryption:** The system does not store a password hash. Instead, it attempts to decrypt the Master Key using the derived key. Success is the only proof of a correct PIN.
* **AES-256-GCM Encryption:** All files are encrypted using AES-GCM (Authenticated Encryption), ensuring both confidentiality and data integrity (detection of tampering).
* **Hardware-Locked Storage:** Critical keys and salts are stored in the iOS Keychain with `ThisDeviceOnly` flags, preventing extraction via iCloud backups or unauthorized syncing.



### 🚀 Key Features
* **Brute-Force Protection (API-Level):** A persistent counter in the Keychain tracks failed attempts. After 10 failed tries, the app triggers a **Secure Wipe**, destroying all keys and encrypted content.
* **Thread-Safe Architecture:** Uses a specialized `VaultKeyCache` and `NSLock` synchronization to ensure 100% thread safety in Swift 6 environments while preventing deadlocks.
* **Path Traversal Defense:** A robust sanitization engine validates all file paths at the component level before I/O operations, preventing "directory traversal" attacks.
* **Memory Security:** The Master Key exists only in RAM while the vault is unlocked and is immediately purged upon locking.

### 🛠 Technical Stack
* **Language:** Swift 6 (Strict Concurrency)
* **Frameworks:** CryptoKit, Security, Foundation
* **Security Standard:** PBKDF2 (NIST SP 800-132 compliant), AES-GCM

---

## 🇩🇪 Deutsche Version

### 🛡️ Sicherheits-Architektur
Die Engine implementiert eine **Zero-Knowledge-Architektur**. Weder der PIN noch der Master-Key werden im Klartext gespeichert.

* **Schlüsselableitung (PBKDF2):** Nutzt 200.000 Iterationen von PBKDF2-SHA256 mit einem einzigartigen 32-Byte Salt, um einen Zwischenschlüssel aus dem PIN abzuleiten. Dies erschwert lokales Brute-Forcing massiv.
* **Verify-by-Decryption:** Es wird kein Passwort-Hash gespeichert. Das System versucht stattdessen, den Master-Key mit dem abgeleiteten Schlüssel zu entschlüsseln. Ein Erfolg ist der einzige Beweis für einen korrekten PIN.
* **AES-256-GCM Verschlüsselung:** Alle Dateien werden mit AES-GCM (Authenticated Encryption) verschlüsselt, was sowohl Vertraulichkeit als auch Datenintegrität (Schutz vor Manipulation) garantiert.
* **Hardware-gebundene Speicherung:** Kritische Schlüssel werden in der iOS Keychain mit `ThisDeviceOnly`-Flags gespeichert, was die Extraktion über iCloud-Backups verhindert.



### 🚀 Hauptmerkmale
* **Brute-Force-Schutz (API-Ebene):** Ein persistenter Zähler in der Keychain trackt Fehlversuche. Nach 10 Versuchen erfolgt eine **Selbstzerstörung (Secure Wipe)** aller Schlüssel und Inhalte.
* **Threadsichere Architektur:** Nutzt einen spezialisierten `VaultKeyCache` und `NSLock`-Synchronisation für 100%ige Threadsicherheit unter Swift 6 ohne Deadlocks.
* **Schutz vor Pfad-Manipulation:** Eine Validierungs-Engine prüft alle Dateipfade auf Komponentenebene vor jeder I/O-Operation, um "Path Traversal"-Angriffe zu verhindern.
* **RAM-Sicherheit:** Der Master-Key existiert nur während der Entsperrung im flüchtigen Speicher und wird beim Sperren sofort gelöscht.

### 🛠 Technischer Stack
* **Sprache:** Swift 6 (Strict Concurrency)
* **Frameworks:** CryptoKit, Security, Foundation
* **Standards:** PBKDF2 (NIST SP 800-132 konform), AES-GCM

---

**Disclaimer:** *This core was refined through extensive peer-review to ensure industry-leading security standards for local data protection.*
