# EnclaveLocker

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2015+%20%7C%20macOS%2012+-lightgrey.svg)](https://developer.apple.com)
[![SPM](https://img.shields.io/badge/SPM-Compatible-brightgreen.svg)](https://swift.org/package-manager)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight, modern Swift package that dramatically simplifies the use of the Keychain and Secure Enclave for creating portable, encrypted documents with dual authentication (passphrase and biometrics).

## Overview

Working with Keychain Services and the Secure Enclave in Swift is notoriously verbose and complex, involving C-style APIs, obscure constants, and manual error handling. `EnclaveLocker` abstracts all of that away, providing a tiny, elegant API for the most common and powerful security pattern:

1.  **Truly Portable Documents:** Encrypt data with a key derived directly from a user's passphrase and a salt. As long as the user has their file and their passphrase, they can open it on any device.
2.  **Biometric Convenience:** Securely store that same derived key in the device-specific Secure Enclave, allowing for fast, convenient unlocking via Touch ID or Face ID.

`EnclaveLocker` handles the ugly parts of key derivation (PBKDF2), Secure Enclave key management, and keychain storage, letting you focus on your application logic.

## Features

- ✅ **Passphrase-Based Key Derivation:** Uses PBKDF2 with a salt to turn a user's passphrase into a strong, 256-bit AES encryption key.
- ✅ **Secure Enclave Integration:** One-line functions to store and retrieve the database key using hardware-backed biometrics.
- ✅ **Truly Portable:** The keychain is only used for the *optional, non-portable* biometric key. The core passphrase mechanism is 100% portable.
- ✅ **Clean, Swifty API:** A tiny surface area with clear, self-documenting types like `EnclaveKey` and `EnclaveSalt`.
- ✅ **Lightweight:** Has only one dependency on the trusted and popular `KeychainAccess` library.

## Installation

### Swift Package Manager

You can add `EnclaveLocker` to your project as a package dependency.

1.  In Xcode, select **File > Add Packages...**
2.  Enter the repository URL: `https://github.com/your-username/EnclaveLocker.git`
3.  Choose the version you want and add the package.

Alternatively, you can add it to your `Package.swift` file:
```swift
dependencies: [
    .package(url: "https://github.com/your-username/EnclaveLocker.git", from: "1.0.0")
]
```

## Usage Guide

Since `EnclaveLocker` makes use of the keychain, ensure that you've added Keychain Sharing capability to your provisioning. The capability allows `EnclaveLocker` to provide support for biometric unlocking.

The core of the library is the `EnclaveLock` class. You initialize it with a unique identifier, which namespaces all keychain items to prevent collisions. For a document-based app, this identifier should be unique per document.

```swift
import EnclaveLocker

// Create a lock instance, unique to this document.
let locker = EnclaveLock(identifier: "com.myapp.document.A8A76EAF-1337-4054-9270-34E3C54321B3")
```

### 1. Provisioning a New Encrypted Document

When the user creates a new document and sets a passphrase for the first time.

```swift
func createEncryptedFile(with passphrase: String, enableBiometrics: Bool) throws {
    // 1. Generate a new, random salt. You will store this alongside your encrypted data.
    let salt = locker.generateSalt()
    
    // 2. Derive a strong encryption key from the passphrase and salt.
    let key = try locker.deriveKey(from: passphrase, salt: salt)

    // 3. Use this key to encrypt your data (e.g., a database file, a zip archive, etc.).
    let encryptedData = try encryptMyData(with: key)
    
    // 4. Save the encrypted data and the salt.
    try encryptedData.write(to: fileURL)
    try saveSaltToMetadata(salt)
    
    // 5. (Optional) If the user wants biometric convenience, store the key in the Secure Enclave.
    if enableBiometrics {
        try locker.storeKeyForBiometrics(key)
    }
}
```

### 2. Unlocking with a Passphrase

When the user opens an existing encrypted document.

```swift
func unlockFile(with passphrase: String) throws -> DecryptedData {
    // 1. Retrieve the salt you stored with the document.
    let salt = try getSaltFromMetadata()
    
    // 2. Re-derive the key. This will only succeed if the passphrase is correct.
    let key = try locker.deriveKey(from: passphrase, salt: salt)

    // 3. Attempt to decrypt your data with the derived key.
    // A failure here means the passphrase was incorrect.
    let encryptedData = try Data(contentsOf: fileURL)
    return try decryptMyData(encryptedData, with: key)
}
```

### 3. Unlocking with Biometrics

When the user chooses to unlock via Touch ID / Face ID.

```swift
func unlockFileWithBiometrics() throws -> DecryptedData {
    // 1. Retrieve the key directly from the Secure Enclave.
    // This will trigger the system's biometric prompt.
    let key = try locker.retrieveKeyWithBiometrics(prompt: "Unlock Your Document")

    // 2. Decrypt your data with the retrieved key.
    let encryptedData = try Data(contentsOf: fileURL)
    return try decryptMyData(encryptedData, with: key)
}
```

### 4. Resetting

To completely remove all keychain items associated with this document (i.e., the biometric key and the Secure Enclave private key).

```swift
// This is a destructive operation.
try locker.reset()
```

This is all you need to build a robust, secure, and portable document encryption system.

## License

`EnclaveLocker` is released under the MIT license. See [LICENSE](LICENSE) for details.

