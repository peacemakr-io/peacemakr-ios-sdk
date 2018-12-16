//
//  Core.swift
//  SDK
//
//  Created by Aman LaChapelle on 11/4/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import Foundation
import CoreCrypto

public enum PeacemakrSDKError: Error {
  case addToKeychainFailed
  case getFromKeychainFailed
  case internalError(what: String)
  case verificationFailed
  case decryptionFailed
}

/**
 Provides the Peacemakr iOS SDK.
 */
public class PeacemakrSDK {
  private let cryptoContext: CryptoContext
  private var rand: RandomDevice
  private let apiKey: String
  private let myKeyCfg = CryptoConfig(
    mode: EncryptionMode.ASYMMETRIC,
    symm_cipher: SymmetricCipher.CHACHA20_POLY1305,
    asymm_cipher: AsymmetricCipher.RSA_4096,
    digest: MessageDigestAlgorithm.SHA3_512
  )
  private let priv_tag = "io.peacemakr.client.private"
  private let pub_tag = "io.peacemakr.client.public"
  // symmetric keys start with this prefix and append the key ID onto it
  private let symm_tag_prefix = "io.peacemakr.client.symmetric."
  
  
  public init(apiKey: String) throws {
    cryptoContext = try CryptoContext()
    rand = PeacemakrRandomDevice()
    self.apiKey = apiKey
  }
  
  public func Register() throws {
    // Generate my keys and store them in the keychain
    let myKey = try PeacemakrKey(config: myKeyCfg, rand: rand)
    let privPem = try myKey.toPem(is_priv: true)
    let pubPem = try myKey.toPem(is_priv: false)
    let pubQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: pub_tag,
                                   kSecValueRef as String: pubPem]
    
    let pubStatus = SecItemAdd(pubQuery as CFDictionary, nil)
    guard pubStatus == errSecSuccess else { throw PeacemakrSDKError.addToKeychainFailed }
    
    let privQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: priv_tag,
                                    kSecValueRef as String: privPem]
    
    let privStatus = SecItemAdd(privQuery as CFDictionary, nil)
    guard privStatus == errSecSuccess else { throw PeacemakrSDKError.addToKeychainFailed }
    
    // TODO: call up to server and register myself
  }
  
  public func PreLoad() throws {
    // TODO: load up my keys
  }
  
  private func storeKey(key: [UInt8], keyID: [UInt8]) throws -> Void {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      throw PeacemakrSDKError.internalError(what: "Could not serialize keyID to string")
    }
    let tag = symm_tag_prefix + keyIDStr!
    
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: tag,
                                kSecValueRef as String: key]
    
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw PeacemakrSDKError.addToKeychainFailed }
  }
  
  private func getKeyByID(cfg: CryptoConfig, keyID: [UInt8]) throws -> PeacemakrKey {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      throw PeacemakrSDKError.internalError(what: "Could not serialize keyID to string")
    }
    let tag = symm_tag_prefix + keyIDStr!
    
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    guard status == errSecSuccess else { throw PeacemakrSDKError.getFromKeychainFailed }
    
    let keyBytes = item as! [UInt8]
    return try PeacemakrKey(config: cfg, bytes: keyBytes)
  }
  
  private func getMyKey(priv: Bool) throws -> PeacemakrKey {
    var tag: String
    if priv {
      tag = priv_tag
    } else {
      tag = pub_tag
    }
    
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    guard status == errSecSuccess else { throw PeacemakrSDKError.getFromKeychainFailed }
    
    let keyBytes = item as! [Int8]
    return try PeacemakrKey(config: myKeyCfg, fileContents: keyBytes, is_priv: priv)
  }
  
  private func selectEncryptionKey() throws -> ([UInt8], CryptoConfig) {
    // TODO: actually select the encryption key (requires swagger generated code)
    let cfg = CryptoConfig(mode: EncryptionMode.SYMMETRIC, symm_cipher: SymmetricCipher.AES_256_GCM, asymm_cipher: AsymmetricCipher.NONE, digest: MessageDigestAlgorithm.SHA3_512)
    return ([], cfg)
  }
  
  /**
   Returns an encrypted and base64 serialized blob that contains \p plaintext.
   Throws an error on failure of encryption or serialization.
   */
  public func Encrypt(_ plaintext: Encryptable) throws -> [UInt8] {
    let (keyID, keyCfg) = try selectEncryptionKey()
    let ptext = Plaintext(data: plaintext.Serialized, aad: keyID)
    
    let key = try getKeyByID(cfg: keyCfg, keyID: keyID)
    let signKey = try getMyKey(priv: true)

    var encrypted = try cryptoContext.Encrypt(
      key: key,
      plaintext: ptext,
      rand: rand
    )
    // Sign the message with my key
    cryptoContext.Sign(senderKey: signKey, plaintext: ptext, ciphertext: &encrypted)
    
    let serialized = try cryptoContext.Serialize(encrypted)
    
    return serialized
  }
  
  private func getKeyID(serialized: [UInt8]) throws -> [UInt8] {
    let keyID = try cryptoContext.ExtractUnverifiedAAD(serialized)
    return keyID.AuthenticatableData
  }
  
  /**
   Deserializes and decrypts \p serialized and stores the output into \p dest.
   Throws an error on failure of deserialization or decryption.
   */
  public func Decrypt(_ serialized: [UInt8], dest: inout Encryptable) throws -> Void {
    let keyID = try getKeyID(serialized: serialized)
    var (deserialized, cfg) = try cryptoContext.Deserialize(serialized)
    
    let key = try getKeyByID(cfg: cfg, keyID: keyID)
    
    let (outPlaintext, needsVerify) = try cryptoContext.Decrypt(key: key, ciphertext: deserialized)
    if needsVerify {
      // TODO: this is incorrect - need the sender's public key
      let signKey = try getMyKey(priv: false)
      if !cryptoContext.Verify(senderKey: signKey, plaintext: outPlaintext, ciphertext: &deserialized) {
        throw PeacemakrSDKError.verificationFailed
      }
    }
    
    dest.Serialized = outPlaintext.EncryptableData
  }
  
}
