//
//  EnclaveLocker.swift
//  EnclaveLocker
//
//  Created by Gemini & Mark Onyschuk on 9/13/25.
//

import Foundation
import Security
import CryptoKit
import CommonCrypto
import KeychainAccess

// MARK: - Public Types

/// A type alias for a raw encryption key, adding semantic clarity to the API.
public typealias EnclaveKey = Data
/// A type alias for a salt value, adding semantic clarity to the API.
public typealias EnclaveSalt = Data

/// A collection of cryptographic utilities for deriving keys and using the Secure Enclave.
public final class EnclaveLock {

    // MARK: - Public Error Type
    public enum Error: Swift.Error, LocalizedError {
        case notProvisioned
        case keyDerivationFailed
        case cryptoKitError(String)
        case secureEnclaveKeyError(String)
        case unexpectedStatus(OSStatus, String?)
        
        public var errorDescription: String? {
            switch self {
            case .notProvisioned:
                return "No key for biometric unlocking has been stored."
            case .keyDerivationFailed:
                return "Failed to derive the encryption key from the passphrase."
            case .cryptoKitError(let message):
                return "A cryptographic error occurred: \(message)"
            case .secureEnclaveKeyError(let message):
                return "A Secure Enclave error occurred: \(message)"
            case .unexpectedStatus(let status, let message):
                let desc = message ?? SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
                return "An unexpected keychain error occurred: \(desc) (code: \(status))"
            }
        }
    }

    // MARK: - Private Properties
    private let identifier: String
    private let account = "default_user"

    private var sePrivateKeyTag: Data { "\(identifier).se_private_key".data(using: .utf8)! }

    /// Initializes a new EnclaveLock utility for a given unique identifier.
    /// - Parameter identifier: A reverse-DNS string to uniquely namespace keychain items (e.g., "com.yourcompany.yourapp.document.UUID").
    public init(identifier: String) {
        self.identifier = identifier
    }

    // MARK: - Public API
    
    /// Derives a strong cryptographic key from a user's passphrase and a salt.
    /// - Parameters:
    ///   - passphrase: The user's passphrase.
    ///   - salt: The salt to use for key derivation.
    /// - Returns: A 32-byte derived key.
    public func deriveKey(from passphrase: String, salt: EnclaveSalt) throws -> EnclaveKey {
        var derivedKey = Data(count: 32)
        let keyLength = derivedKey.count
        
        let result = derivedKey.withUnsafeMutableBytes { dkBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passphrase, passphrase.utf8.count, saltBytes.baseAddress, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 100_000, dkBytes.baseAddress, keyLength)
            }
        }
        guard result == kCCSuccess else { throw Error.keyDerivationFailed }
        return derivedKey
    }
    
    /// Generates a new, random salt suitable for key derivation.
    /// - Returns: A 16-byte random salt.
    public func generateSalt() -> EnclaveSalt {
        var data = Data(count: 16)
        _ = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        return data
    }
    
    /// Encrypts the provided key using the Secure Enclave and stores it in the keychain for biometric access.
    /// - Parameter key: The raw database key to be stored.
    public func storeKeyForBiometrics(_ key: EnclaveKey) throws {
        let privateKey = try getOrCreateSEPrivateKey()
        let encryptedKey = try encryptWithSEKey(key, publicKey: SecKeyCopyPublicKey(privateKey)!)
        try saveData(encryptedKey, for: identifier)
    }

    /// Retrieves the stored database key using device biometrics.
    /// - Parameter prompt: The reason string displayed to the user in the biometric prompt.
    /// - Returns: The decrypted database key.
    public func retrieveKeyWithBiometrics(prompt: String) throws -> EnclaveKey {
        guard let encryptedKey = try readData(from: identifier) else { throw Error.notProvisioned }
        let privateKey = try getOrCreateSEPrivateKey()
        return try decryptWithSEKey(encryptedKey, privateKey: privateKey, prompt: prompt)
    }

    /// Deletes all keychain items (biometric key and Secure Enclave key) associated with this identifier.
    public func reset() throws {
        try deleteData(for: identifier)
        try deleteSEPrivateKey()
    }
    
    // MARK: - Secure Enclave & Crypto Primitives
    
    private func getOrCreateSEPrivateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: sePrivateKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let key = item { return (key as! SecKey) }
        
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error)!
        
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: sePrivateKeyTag,
                kSecAttrAccessControl as String: access
            ]
        ]
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Error.secureEnclaveKeyError("Could not create the Secure Enclave private key. \(error!.takeRetainedValue() as Swift.Error)")
        }
        return privateKey
    }
    
    private func encryptWithSEKey(_ data: Data, publicKey: SecKey) throws -> Data {
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, .eciesEncryptionStandardX963SHA256AESGCM) else { throw Error.secureEnclaveKeyError("ECIES encryption not supported.") }
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .eciesEncryptionStandardX963SHA256AESGCM, data as CFData, &error) as Data? else {
            throw Error.secureEnclaveKeyError("Encryption with SE public key failed: \(error!.takeRetainedValue())")
        }
        return encryptedData
    }
    
    private func decryptWithSEKey(_ encryptedData: Data, privateKey: SecKey, prompt: String) throws -> Data {
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, .eciesEncryptionStandardX963SHA256AESGCM) else { throw Error.secureEnclaveKeyError("ECIES decryption not supported.") }
        
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey, .eciesEncryptionStandardX963SHA256AESGCM, encryptedData as CFData, &error) as Data? else {
            let err = error?.takeRetainedValue()
            throw Error.secureEnclaveKeyError("Decryption failed. User may have cancelled. OSStatus: \(err.debugDescription)")
        }
        return decryptedData
    }
    
    private func deleteSEPrivateKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: sePrivateKeyTag
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound { throw Error.unexpectedStatus(status, "Failed to delete SE key.") }
    }

    // MARK: - Keychain CRUD Helpers (using KeychainAccess)
    
    private func saveData(_ data: Data, for service: String) throws {
        let keychain = Keychain(service: service)
        try keychain.set(data, key: account)
    }

    private func readData(from service: String) throws -> Data? {
        let keychain = Keychain(service: service)
        return try keychain.getData(account)
    }

    private func deleteData(for service: String) throws {
        let keychain = Keychain(service: service)
        try keychain.remove(account)
    }
}
