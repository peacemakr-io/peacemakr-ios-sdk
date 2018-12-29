//
//  Core.swift
//  SDK
//
//  Created by Aman LaChapelle on 11/4/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import Foundation
import CoreCrypto

/**
 Provides the Peacemakr iOS SDK.
 */
public class PeacemakrSDK {
  private let version = "0.1.0"
  private let cryptoContext: CryptoContext
  private var rand: RandomDevice
  private let apiKey: String
  private var logHandler: (String) -> Void
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
  
  public init?(apiKey: String, logHandler: @escaping (String)->Void) {
    let cc = CryptoContext()
    if cc == nil {
      return nil
    }
    cryptoContext = cc!
    rand = PeacemakrRandomDevice()
    self.apiKey = apiKey
    self.logHandler = logHandler
  }
  
  private func sendRequest<T>(builder: RequestBuilder<T>, completion: @escaping (_ response: T?, _ error: Error?) -> Void) -> Void {
    builder.addHeaders(["authorization": self.apiKey])
    builder.execute({ (response, error) -> Void in
      completion(response?.body, error)
    })
  }
  
  private func getMyClientID() -> String? {
    let pubKeyIDQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                        kSecAttrApplicationTag as String: self.clientIDTag,
                                        kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(pubKeyIDQuery as CFDictionary, &item)
    guard status == errSecSuccess else {
      self.logHandler("failed to get my client ID from the keychain")
      return nil
    }
    
    return String(bytes: item as! [UInt8], encoding: .utf8)
  }
  
  public func Register() -> Bool {
    // Generate my keys and store them in the keychain
    let myKey = PeacemakrKey(config: myKeyCfg, rand: rand)
    if myKey == nil {
      self.logHandler("Keygen failed")
      return false
    }
    let priv = UnwrapCall(myKey!.toPem(is_priv: true), onError: self.logHandler)
    if priv == nil {
      self.logHandler("priv key to pem failed")
      return false
    }
    let privPem = priv!
    
    let pub = UnwrapCall(myKey!.toPem(is_priv: false), onError: self.logHandler)
    if pub == nil {
      self.logHandler("pub key to pem failed")
      return false
    }
    let pubPem = pub!
    
    let pubQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: self.pubTag,
                                   kSecValueRef as String: pubPem]
    
    let pubStatus = SecItemAdd(pubQuery as CFDictionary, nil)
    guard pubStatus == errSecSuccess else {
      self.logHandler("Failed to add public key to keychain")
      return false
    }
    
    let privQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: self.privTag,
                                    kSecValueRef as String: privPem]
    
    let privStatus = SecItemAdd(privQuery as CFDictionary, nil)
    guard privStatus == errSecSuccess else {
      self.logHandler("Failed to add private key to keychain")
      return false
    }
    
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
    var success = true
    sendRequest(builder: requestBuilder, completion: {(client, error) in
      // Store the clientID and publicKeyID into the keychain as well
      let clientID = client?.id?.utf8
      let clientIDQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                          kSecAttrApplicationTag as String: self.clientIDTag,
                                          kSecValueRef as String: Array(clientID!)]
      if SecItemAdd(clientIDQuery as CFDictionary, nil) != errSecSuccess {
        self.logHandler("Failed to add client ID tto keychain")
        success = false
        return
      }
      
      let pubKeyID = client?.publicKey?.id?.utf8
      let pubKeyIDQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                          kSecAttrApplicationTag as String: self.pubKeyIDTag,
                                          kSecValueRef as String: Array(pubKeyID!)]
      
      if SecItemAdd(pubKeyIDQuery as CFDictionary, nil) != errSecSuccess {
        self.logHandler("Failed to add public key ID to keychain")
        success = false
        return
      }
    })
    
    return success
  }
  
  public func PreLoad() -> Bool {
    self.logHandler("Unimplemented")
    return false
  }
  
  private func storeKey(key: [UInt8], keyID: [UInt8]) -> Bool {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      self.logHandler("Could not serialize keyID to string")
      return false
    }
    let tag = symmTagPrefix + keyIDStr!
    
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: tag,
                                kSecValueRef as String: key]
    
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
      self.logHandler("could not add symmetric key: " + keyIDStr! + " to keychain")
      return false
    }
    
    return true
  }
  
  private func getPublicKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    var outKeyPem: [CChar] = []
    let requestBuilder = KeyServiceAPI.getPublicKeyWithRequestBuilder(keyID: String(bytes: keyID, encoding: .utf8)!)
    sendRequest(builder: requestBuilder, completion: {(key, error) in
      let keyStr = key?.key
      outKeyPem = Array(keyStr!.utf8CString)
    })
    
    // todo: cache public keys?
    return PeacemakrKey(config: cfg, fileContents: outKeyPem, is_priv: false)
  }
  
  private func getLocalKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      self.logHandler("Could not marshal keyID to string")
      return nil
    }
    let tag = symmTagPrefix + keyIDStr!
    
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    guard status == errSecSuccess else {
      self.logHandler("could not get symmetric key: " + keyIDStr! + " from keychain")
      return nil
    }
    
    let keyBytes = item as! [UInt8]
    return PeacemakrKey(config: cfg, bytes: keyBytes)
  }
  
  private func getSymmKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let symmKey = getLocalKeyByID(keyID: keyID, cfg: cfg)
    if symmKey != nil {
      return symmKey
    }
    
    // this means that we don't have the key we need, so go up to server and get the key we need
    let myClientID = getMyClientID()
    if myClientID == nil {
      self.logHandler("Unable to get client ID")
      return nil
    }
    
    let requestBuilder = KeyServiceAPI.getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: myClientID!, symmetricKeyIds: [String(bytes: keyID, encoding: .utf8)!])
    let myPrivKey = getMyKey(priv: true)
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
      if serialized == nil {
        self.logHandler("key package:" + (key.symmetricKeyUseDomainId ?? "unknown") + " ciphertext not present")
        return nil
      }
      
      let storedKeyIDs = getKeyID(serialized: Array(serialized!))
      if storedKeyIDs == nil {
        self.logHandler("Unable to extract key IDs serialized key package")
        return nil
      }
      
      let (_, signKeyID) = storedKeyIDs!
      let deserializedCfg = UnwrapCall(cryptoContext.Deserialize(Array(serialized!)), onError: self.logHandler)
      if deserializedCfg == nil {
        self.logHandler("Unable to deserialize key package ciphertext")
        return nil
      }
      var (deserialized, _) = deserializedCfg!
      
      let decryptResult = UnwrapCall(cryptoContext.Decrypt(key: myPrivKey!, ciphertext: deserialized), onError: self.logHandler)
      if decryptResult == nil {
        self.logHandler("Unable to decrypt key package ciphertext")
        return nil
      }
      
      let (keyPlaintext, needVerify) = decryptResult!
      if needVerify {
        let signKey = getPublicKeyByID(keyID: signKeyID, cfg: myKeyCfg)
        let verified = UnwrapCall(cryptoContext.Verify(senderKey: signKey!, plaintext: keyPlaintext, ciphertext: &deserialized), onError: self.logHandler)
        if verified == nil || verified! == false {
          self.logHandler("Verification of key package failed")
          return nil
        }
      }
      
      guard let keyBytes = Data(base64Encoded: String(bytes: keyPlaintext.EncryptableData, encoding: .utf8)!) else {
        self.logHandler("Invalid b64 key")
        return nil
      }
      
      let keyLen = Int(key.keyLength!)
      let keyIDs = key.keyIds!
      for (i, keyID) in keyIDs.enumerated() {
        let thisKeyBytes = keyBytes[i*keyLen..<(i+1)*keyLen]
        if !storeKey(key: Array(thisKeyBytes), keyID: Array(keyID.utf8)) {
          self.logHandler("Storing key failed")
          return nil
        }
      }
    }
    
    // Try again now that I've gotten the key
    return getSymmKeyByID(keyID: keyID, cfg: cfg)
  }
  
  private func getMyKey(priv: Bool) -> PeacemakrKey? {
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
    guard status == errSecSuccess else {
      self.logHandler("unable to get my key (public/private) from keychain")
      return nil
    }
    
    let keyBytes = item as! [Int8]
    return PeacemakrKey(config: myKeyCfg, fileContents: keyBytes, is_priv: priv)
  }
  
  private func selectEncryptionKey() -> ([UInt8], CoreCrypto.CryptoConfig)? {
    // TODO: actually select the encryption key (requires swagger generated code)
    let cfg = CoreCrypto.CryptoConfig(mode: EncryptionMode.SYMMETRIC, symm_cipher: SymmetricCipher.AES_256_GCM, asymm_cipher: AsymmetricCipher.NONE, digest: MessageDigestAlgorithm.SHA3_512)
    return ([], cfg)
  }
  
  private func getMyPublicKeyID() -> [UInt8]? {
    let pubKeyIDQuery: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                        kSecAttrApplicationTag as String: self.pubKeyIDTag,
                                        kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(pubKeyIDQuery as CFDictionary, &item)
    guard status == errSecSuccess else {
      self.logHandler("unable to get my public key ID from keychain:")
      return nil
    }
    
    return item as! [UInt8]
  }
  
  /**
   Returns an encrypted and base64 serialized blob that contains \p plaintext.
   Throws an error on failure of encryption or serialization.
   */
  public func Encrypt(_ plaintext: Encryptable) -> [UInt8]? {
    let selectedKey = selectEncryptionKey()
    if selectedKey == nil {
      self.logHandler("Unable to select encryption key")
      return nil
    }
    
    let (keyID, keyCfg) = selectedKey!
    let aadJSON = try? JSONSerialization.data(withJSONObject: ["cryptoKeyID": keyID, "senderKeyID": getMyPublicKeyID()], options: [])
    if aadJSON == nil {
      self.logHandler("Failed to serialize the key IDs to json")
      return nil
    }
    let messageAAD = String(data: aadJSON!, encoding: .utf8)
    
    let ptext = Plaintext(data: plaintext.Serialized, aad: Array(messageAAD!.utf8))
    
    let key = getSymmKeyByID(keyID: keyID, cfg: keyCfg)
    if key == nil {
      self.logHandler("Unable to get the encryption key: " + String(bytes: keyID, encoding: .utf8)!)
      return nil
    }
    let signKey = getMyKey(priv: true)
    if signKey == nil {
      self.logHandler("Unable to get my private key")
      return nil
    }

    var encrypted = UnwrapCall(cryptoContext.Encrypt(
      key: key!,
      plaintext: ptext,
      rand: rand
    ), onError: self.logHandler)
    if encrypted == nil {
      self.logHandler("Encryption failed")
      return nil
    }
    
    // Sign the message with my key
    cryptoContext.Sign(senderKey: signKey!, plaintext: ptext, ciphertext: &encrypted!)
    
    let serialized = UnwrapCall(cryptoContext.Serialize(encrypted!), onError: self.logHandler)
    if serialized == nil {
      self.logHandler("Serialization failed")
      return nil
    }
    
    return serialized
  }
  
  private func getKeyID(serialized: [UInt8]) -> ([UInt8], [UInt8])? {
    let serializedAAD = UnwrapCall(cryptoContext.ExtractUnverifiedAAD(serialized), onError: self.logHandler)
    if serializedAAD == nil {
      return nil
    }
    
    let aadDict = try? JSONSerialization.jsonObject(with: Data(bytes: serializedAAD!.AuthenticatableData), options: [])
    if aadDict == nil {
      self.logHandler("json deserialization of AAD failed")
      return nil
    }
    
    let aad = aadDict as! Dictionary<String, [UInt8]>
    
    return (aad["cryptoKeyID"]!, aad["senderKeyID"]!)
  }
  
  /**
   Deserializes and decrypts \p serialized and stores the output into \p dest.
   Throws an error on failure of deserialization or decryption.
   */
  public func Decrypt(_ serialized: [UInt8], dest: inout Encryptable) -> Bool {
    let keyIDs = getKeyID(serialized: serialized)
    if keyIDs == nil {
      self.logHandler("Unable to parse key IDs from message")
      return false
    }
    
    let (keyID, signKeyID) = keyIDs!
    let deserializedCfg = UnwrapCall(cryptoContext.Deserialize(serialized), onError: self.logHandler)
    if deserializedCfg == nil {
      self.logHandler("Unable to deserialize encrypted message")
      return false
    }
    var (deserialized, cfg) = deserializedCfg!
    
    let key = getSymmKeyByID(keyID: keyID, cfg: cfg)
    if key == nil {
      self.logHandler("Unable to get symmetric key for decrypting the messaage")
      return false
    }
    
    let decryptResult = UnwrapCall(cryptoContext.Decrypt(key: key!, ciphertext: deserialized), onError: self.logHandler)
    if decryptResult == nil {
      self.logHandler("Decryption failed")
      return false
    }
    
    let (outPlaintext, needsVerify) = decryptResult!
    if needsVerify {
      // the key configs for all clients are the same here
      let signKey = getPublicKeyByID(keyID: signKeyID, cfg: myKeyCfg)
      if signKey == nil {
        self.logHandler("Unable to get the public key for keyID: " + String(bytes: signKeyID, encoding: .utf8)!)
        return false
      }
      
      if !UnwrapCall(cryptoContext.Verify(senderKey: signKey!, plaintext: outPlaintext, ciphertext: &deserialized), onError: self.logHandler)! {
        self.logHandler("Verification failed")
        return false
      }
    }
    
    dest.Serialized = outPlaintext.EncryptableData
    return true
  }
  
}
