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
  case addToKeychainFailed(what: String)
  case getFromKeychainFailed(what: String)
  case internalError(what: String)
  case verificationFailed
  case decryptionFailed
  case jsonSerializeFailed
  case jsonDeserializeFailed
  case unimplemented
}

/**
 Provides the Peacemakr iOS SDK.
 */
public class PeacemakrSDK {
  private let version = "0.1.0"
  private let cryptoContext: CryptoContext
  private var rand: RandomDevice
  private let apiKey: String
  private let myKeyCfg = CoreCrypto.CryptoConfig(
    mode: EncryptionMode.ASYMMETRIC,
    symm_cipher: SymmetricCipher.AES_256_GCM,
    asymm_cipher: AsymmetricCipher.RSA_4096,
    digest: MessageDigestAlgorithm.SHA3_512
  )
  private let privTag = "io.peacemakr.client.private"
  private let pubTag = "io.peacemakr.client.public"
  // symmetric keys start with this prefix and append the key ID onto it
  private let symmTagPrefix = "io.peacemakr.client.symmetric."
  
  private let clientIDTag = "io.peacemakr.client.id"
  private let pubKeyIDTag = "io.peacemakr.client.public.id"
  
  
  public init(apiKey: String) throws {
    cryptoContext = try CryptoContext()
    rand = PeacemakrRandomDevice()
    self.apiKey = apiKey
  }
  
  private func sendRequest<T>(builder: RequestBuilder<T>, completion: @escaping (_ response: T?, _ error: Error?) -> Void) -> Void {
    builder.addHeaders(["authorization": self.apiKey])
    builder.execute({ (response, error) -> Void in
      completion(response?.body, error)
    })
  }
  
  private func getMyClientID() throws -> String? {
    let pubKeyIDQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                        kSecAttrApplicationTag as String: self.clientIDTag,
                                        kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(pubKeyIDQuery as CFDictionary, &item)
    guard status == errSecSuccess else { throw PeacemakrSDKError.getFromKeychainFailed(what: "my client ID") }
    
    return String(bytes: item as! [UInt8], encoding: .utf8)
  }
  
  public func Register() throws {
    // Generate my keys and store them in the keychain
    let myKey = try PeacemakrKey(config: myKeyCfg, rand: rand)
    let privPem = try myKey.toPem(is_priv: true)
    let pubPem = try myKey.toPem(is_priv: false)
    let pubQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: self.pubTag,
                                   kSecValueRef as String: pubPem]
    
    let pubStatus = SecItemAdd(pubQuery as CFDictionary, nil)
    guard pubStatus == errSecSuccess else { throw PeacemakrSDKError.addToKeychainFailed(what: "Public Key") }
    
    let privQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: self.privTag,
                                    kSecValueRef as String: privPem]
    
    let privStatus = SecItemAdd(privQuery as CFDictionary, nil)
    guard privStatus == errSecSuccess else { throw PeacemakrSDKError.addToKeychainFailed(what: "Private Key") }
    
    // Call up to server and register myself
    let registerClient = Client()
    registerClient.sdk = version
    registerClient.id = "" // will be populated with my client ID by the server
    registerClient.publicKey?.creationTime = Int32(Date().timeIntervalSince1970)
    registerClient.publicKey?.encoding = "pem"
    registerClient.publicKey?.id = "" // will be populated with my public key ID by the server
    registerClient.publicKey?.key = String(cString: pubPem)
    registerClient.publicKey?.keyType = "rsa"
    
    let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)
    sendRequest(builder: requestBuilder, completion: {(client, error) in
      // Store the clientID and publicKeyID into the keychain as well
      let clientID = client?.id?.utf8
      let clientIDQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                          kSecAttrApplicationTag as String: self.clientIDTag,
                                          kSecValueRef as String: Array(clientID!)]
      if SecItemAdd(clientIDQuery as CFDictionary, nil) != errSecSuccess {
        // TODO: log
      }
      
      let pubKeyID = client?.publicKey?.id?.utf8
      let pubKeyIDQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                          kSecAttrApplicationTag as String: self.pubKeyIDTag,
                                          kSecValueRef as String: Array(pubKeyID!)]
      
      if SecItemAdd(pubKeyIDQuery as CFDictionary, nil) != errSecSuccess {
        // TODO: log
      }
    })
  }
  
  public func PreLoad() throws {
    throw PeacemakrSDKError.unimplemented
  }
  
  private func storeKey(key: [UInt8], keyID: [UInt8]) throws -> Void {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      throw PeacemakrSDKError.internalError(what: "Could not serialize keyID to string")
    }
    let tag = symmTagPrefix + keyIDStr!
    
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: tag,
                                kSecValueRef as String: key]
    
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw PeacemakrSDKError.addToKeychainFailed(what: "symmetric key: " + keyIDStr!) }
  }
  
  private func getPublicKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) throws -> PeacemakrKey {
    var outKeyPem: [CChar] = []
    let requestBuilder = KeyServiceAPI.getPublicKeyWithRequestBuilder(keyID: String(bytes: keyID, encoding: .utf8)!)
    sendRequest(builder: requestBuilder, completion: {(key, error) in
      let keyStr = key?.key
      outKeyPem = Array(keyStr!.utf8CString)
    })
    
    // todo: cache public keys?
    return try PeacemakrKey(config: cfg, fileContents: outKeyPem, is_priv: false)
  }
  
  private func getLocalKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) throws -> PeacemakrKey {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      throw PeacemakrSDKError.internalError(what: "Could not marshal keyID to string")
    }
    let tag = symmTagPrefix + keyIDStr!
    
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    guard status == errSecSuccess else { throw PeacemakrSDKError.getFromKeychainFailed(what: "symmetric key: " + keyIDStr!) }
    
    let keyBytes = item as! [UInt8]
    return try PeacemakrKey(config: cfg, bytes: keyBytes)
  }
  
  private func getSymmKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) throws -> PeacemakrKey {
    do {
      return try getLocalKeyByID(keyID: keyID, cfg: cfg)
    } catch PeacemakrSDKError.getFromKeychainFailed {
      // this means that we don't have the key we need, so go up to server and get the key we need
      let myClientID = try getMyClientID()
      if (myClientID == nil) {
        throw PeacemakrSDKError.internalError(what: "Unable to get client ID")
      }
      
      let requestBuilder = KeyServiceAPI.getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: myClientID!, symmetricKeyIds: [String(bytes: keyID, encoding: .utf8)!])
      let myPrivKey = try getMyKey(priv: true)
      var keysInRequest: [EncryptedSymmetricKey] = []
      sendRequest(builder: requestBuilder, completion: {(keys, error) in
        if keys == nil {
          // TODO: log
          return
        }
        keysInRequest = keys!
      })
      
      for key in keysInRequest {
        let serialized = key.packagedCiphertext?.utf8
        
        let (_, signKeyID) = try getKeyID(serialized: Array(serialized!))
        var (deserialized, _) = try cryptoContext.Deserialize(Array(serialized!))
        
        let (keyPlaintext, needVerify) = try cryptoContext.Decrypt(key: myPrivKey, ciphertext: deserialized)
        if needVerify {
          let signKey = try getPublicKeyByID(keyID: signKeyID, cfg: myKeyCfg)
          if !cryptoContext.Verify(senderKey: signKey, plaintext: keyPlaintext, ciphertext: &deserialized) {
            throw PeacemakrSDKError.verificationFailed
          }
        }
        
        guard let keyBytes = Data(base64Encoded: String(bytes: keyPlaintext.EncryptableData, encoding: .utf8)!) else {
          throw PeacemakrSDKError.internalError(what: "Invalid b64 key")
        }
        
        let keyLen = Int(key.keyLength!)
        let keyIDs = key.keyIds!
        for (i, keyID) in keyIDs.enumerated() {
          let thisKeyBytes = keyBytes[i*keyLen..<(i+1)*keyLen]
          try storeKey(key: Array(thisKeyBytes), keyID: Array(keyID.utf8))
        }
      }
      
      // Try again now that I've gotten the key
      return try getSymmKeyByID(keyID: keyID, cfg: cfg)
    }
    // Other errors should get bubbled up
  }
  
  private func getMyKey(priv: Bool) throws -> PeacemakrKey {
    var tag: String
    if priv {
      tag = privTag
    } else {
      tag = pubTag
    }
    
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    guard status == errSecSuccess else { throw PeacemakrSDKError.getFromKeychainFailed(what: "public/private key") }
    
    let keyBytes = item as! [Int8]
    return try PeacemakrKey(config: myKeyCfg, fileContents: keyBytes, is_priv: priv)
  }
  
  private func selectEncryptionKey() throws -> ([UInt8], CoreCrypto.CryptoConfig) {
    // TODO: actually select the encryption key (requires swagger generated code)
    let cfg = CoreCrypto.CryptoConfig(mode: EncryptionMode.SYMMETRIC, symm_cipher: SymmetricCipher.AES_256_GCM, asymm_cipher: AsymmetricCipher.NONE, digest: MessageDigestAlgorithm.SHA3_512)
    return ([], cfg)
  }
  
  private func getMyPublicKeyID() throws -> [UInt8] {
    let pubKeyIDQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                        kSecAttrApplicationTag as String: self.pubKeyIDTag,
                                        kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(pubKeyIDQuery as CFDictionary, &item)
    guard status == errSecSuccess else { throw PeacemakrSDKError.getFromKeychainFailed(what: "my public key") }
    
    return item as! [UInt8]
  }
  
  /**
   Returns an encrypted and base64 serialized blob that contains \p plaintext.
   Throws an error on failure of encryption or serialization.
   */
  public func Encrypt(_ plaintext: Encryptable) throws -> [UInt8] {
    let (keyID, keyCfg) = try selectEncryptionKey()
    let aadJSON = try? JSONSerialization.data(withJSONObject: ["cryptoKeyID": keyID, "senderKeyID": getMyPublicKeyID()], options: [])
    if aadJSON == nil {
      throw PeacemakrSDKError.jsonSerializeFailed
    }
    let messageAAD = String(data: aadJSON!, encoding: .utf8)
    
    let ptext = Plaintext(data: plaintext.Serialized, aad: Array(messageAAD!.utf8))
    
    let key = try getSymmKeyByID(keyID: keyID, cfg: keyCfg)
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
  
  private func getKeyID(serialized: [UInt8]) throws -> ([UInt8], [UInt8]) {
    let serializedAAD = try cryptoContext.ExtractUnverifiedAAD(serialized)
    let aadDict = try? JSONSerialization.jsonObject(with: Data(bytes: serializedAAD.AuthenticatableData), options: [])
    if aadDict == nil {
      throw PeacemakrSDKError.jsonDeserializeFailed
    }
    
    let aad = aadDict as! Dictionary<String, [UInt8]>
    
    return (aad["cryptoKeyID"]!, aad["senderKeyID"]!)
  }
  
  /**
   Deserializes and decrypts \p serialized and stores the output into \p dest.
   Throws an error on failure of deserialization or decryption.
   */
  public func Decrypt(_ serialized: [UInt8], dest: inout Encryptable) throws -> Void {
    let (keyID, signKeyID) = try getKeyID(serialized: serialized)
    var (deserialized, cfg) = try cryptoContext.Deserialize(serialized)
    
    let key = try getSymmKeyByID(keyID: keyID, cfg: cfg)
    
    let (outPlaintext, needsVerify) = try cryptoContext.Decrypt(key: key, ciphertext: deserialized)
    if needsVerify {
      // the key configs for all clients are the same here
      let signKey = try getPublicKeyByID(keyID: signKeyID, cfg: myKeyCfg)
      
      if !cryptoContext.Verify(senderKey: signKey, plaintext: outPlaintext, ciphertext: &deserialized) {
        throw PeacemakrSDKError.verificationFailed
      }
    }
    
    dest.Serialized = outPlaintext.EncryptableData
  }
  
}
