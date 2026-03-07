# Privr-Security-Core - Transparent Encryption for iOS
This repository contains the core encryption logic for the Privr Photo Vault app. To ensure maximum transparency, we are open-sourcing the mechanisms that protect sensitive data on the device.

[English Version below](#english-version)

---

## Deutsche Version

Dieses Repository enthält den Kern der Verschlüsselungslogik für die **Privr Photo Vault** App. Um maximales Vertrauen zu schaffen, lege ich offen, wie sensible Daten auf dem iPad geschützt werden. In einer Zeit, in der Privatsphäre oft ein Versprechen bleibt, setzen wir auf Transparenz.

### 🛡️ Sicherheitsarchitektur

Der `SecurityManager.swift` nutzt Industriestandards, um sicherzustellen, dass Daten auch bei physischem Zugriff auf das Gerät geschützt bleiben.

#### 1. Schlüsselhierarchie & Ableitung
Wir verwenden eine zweistufige Schlüsselhierarchie:
* **User-Key:** Abgeleitet aus dem 6-stelligen Nutzer-PIN mittels **HKDF (SHA256)** und einem statischen Salt.
* **Master-Key:** Ein zufällig generierter **AES-256 Schlüssel**, der mit dem User-Key verschlüsselt in der iOS Keychain gespeichert wird.
* **Dateiverschlüsselung:** Jedes Bild wird mit dem Master-Key mittels **AES-256-GCM** (Galois/Counter Mode) verschlüsselt. Dieser Modus bietet sowohl Vertraulichkeit als auch Authentizität (Schutz vor Manipulation).

#### 2. Speicherorte
* **Schlüssel:** Werden ausschließlich in der **Apple Keychain** (Secure Enclave) gespeichert, mit dem Attribut `.accessibleAfterFirstUnlock`.
* **Daten:** Die verschlüsselten Binärdaten liegen im `Documents`-Verzeichnis der App mit aktivierter `completeFileProtection`.

#### 3. Swift 6 & Performance
Der Code wurde vollständig auf den **Swift 6 Language Mode** optimiert:
* **Thread-Sicherheit:** Konsequente Nutzung von `nonisolated` Methoden und `Sendable` Typen, um Data Races auf Compiler-Ebene auszuschließen.
* **OOM-Schutz:** Einsatz von `autoreleasepool` und asynchronem Laden von Thumbnails, um den Arbeitsspeicher bei großen Bibliotheken (getestet bis 3GB+) zu schonen.
* **Fluid UX:** Nutzung von `Task.yield()` und Hintergrund-Prioritäten (`.utility`), um die Benutzeroberfläche auch während massiver Entschlüsselungsprozesse flüssig zu halten.

### 🔍 Feedback erwünscht (Peer Review)
Ich lade Entwickler herzlich ein, die Implementierung zu prüfen. Besonders kritische Blicke auf folgende Punkte sind willkommen:
1.  Ist die Schlüsselableitung via HKDF für einen 6-stelligen PIN ausreichend gehärtet?
2.  Gibt es Optimierungspotenzial bei der Nutzung von `AES.GCM.SealedBox`?
3.  Sind die `nonisolated` Zugriffe im `SecurityManager` unter Swift 6 korrekt evaluiert?

---

## English Version

This repository contains the core encryption logic for the **Privr Photo Vault** app. To ensure maximum transparency and security, we are open-sourcing the mechanisms that protect sensitive data on iOS.

### 🛡️ Security Architecture

The `SecurityManager.swift` utilizes industry-standard protocols to ensure data remains secure even if physical access to the device is obtained.

#### 1. Key Hierarchy & Derivation
We use a two-tier key hierarchy:
* **User Key:** Derived from the user's 6-digit PIN using **HKDF (SHA256)** with a static salt.
* **Master Key:** A randomly generated **AES-256 key**, stored in the iOS Keychain and encrypted with the User Key.
* **File Encryption:** Every image is encrypted with the Master Key using **AES-256-GCM** (Galois/Counter Mode). This mode provides both confidentiality and data integrity (AEAD).

#### 2. Storage Strategy
* **Keys:** Stored exclusively in the **Apple Keychain** (Secure Enclave) using the `.accessibleAfterFirstUnlock` attribute.
* **Data:** Encrypted binary data is stored in the app's `Documents` directory with `completeFileProtection` enabled.

#### 3. Swift 6 & Performance Optimization
The codebase is fully optimized for the **Swift 6 Language Mode**:
* **Thread Safety:** Leveraging `nonisolated` methods and `Sendable` protocols to prevent Data Races.
* **Memory Management:** Utilizing `autoreleasepool` and asynchronous thumbnail loading to prevent Out-Of-Memory (OOM) crashes during mass decryption (tested with 3GB+ datasets).
* **Responsiveness:** Implementation of background priorities (`.utility`) ensuring the UI remains responsive at 60/120 FPS.

### 🔍 Call for Peer Review
I invite developers and security researchers to audit this implementation. Specific areas of interest for feedback include:
1.  HKDF derivation hardening for 6-digit passcodes.
2.  Potential optimizations for the `AES.GCM.SealedBox` implementation.
3.  Swift 6 Concurrency model application within the `SecurityManager` extensions.

---

## License
This project is provided for transparency and review purposes. See the `LICENSE` file for details (e.g., MIT License).
