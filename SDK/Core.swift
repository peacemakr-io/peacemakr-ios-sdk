//
//  Core.swift
//  SDK
//
//  Created by Aman LaChapelle on 11/4/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import Foundation
import CoreCrypto

import os.log

/**
 Provides the Peacemakr iOS SDK.
 */
public class PeacemakrSDK {
  private let version = "0.0.1"
  private let cryptoContext: CryptoContext
  private var rand: RandomDevice = PeacemakrRandomDevice()
  private let apiKey: String
  private var logHandler: (PeacemakrError) -> Void
  private let myKeyCfg = CoreCrypto.CryptoConfig(
    mode: EncryptionMode.ASYMMETRIC,
    symm_cipher: SymmetricCipher.AES_256_GCM,
    asymm_cipher: AsymmetricCipher.RSA_4096,
    digest: MessageDigestAlgorithm.SHA3_512
  )
  
  private let dataPrefix = "io.peacemakr.client."
  private let privTag = "io.peacemakr.client.private"
  private let pubTag = "io.peacemakr.client.public"
  // symmetric keys start with this prefix and append the key ID onto it
  private let symmTagPrefix = "io.peacemakr.client.symmetric."
  
  private let clientIDTag = "ClientID"
  private let pubKeyIDTag = "PubKeyID"
  
  private let persister: Persister
  
  public init?(apiKey: String, basePath: String = "") {
    self.apiKey = apiKey
    self.logHandler = { (err) in
      print(err.description)
    }
    
    let cc = CryptoContext()
    cryptoContext = cc!
    
    self.persister = DefaultPersister(logHandler: self.logHandler)
    
    if cc == nil {
      self.log(PeacemakrError(what: "Unable to init CryptoContext", subsystem: .Crypto, shouldSend: true))
      return nil
    }
    
    if basePath == "" {
      SwaggerClientAPI.basePath = SwaggerClientAPI.basePath.replacingOccurrences(of: "http", with: "https")
    } else {
      SwaggerClientAPI.basePath = basePath
    }
    
    SwaggerClientAPI.customHeaders = ["Authorization": self.apiKey]
  }
  
  private func log(_ e: PeacemakrError) -> Void {
    let logStr = e.description
    
    if self.RegistrationSuccessful && e.shouldSend {
      let logEvent = Log(clientId: myClientID, event: logStr)
      
      let requestBuilder = PhoneHomeAPI.logPostWithRequestBuilder(log: logEvent)
      requestBuilder.execute({(response, error) in
        if error != nil {
          let err = PeacemakrError(what: error!.localizedDescription, subsystem: .Network, shouldSend: false)
          self.logHandler(err)
        }
      })
    }
    
    self.logHandler(e)
  }
  
  public var RegistrationSuccessful: Bool {
    get {
      return self.persister.hasData(self.dataPrefix + self.clientIDTag) && self.persister.hasData(self.dataPrefix + self.pubKeyIDTag)
    }
  }
  
  private var myClientID: String {
    get {
      let clientID: String? = self.persister.getData(self.dataPrefix + self.clientIDTag)
      if clientID == nil {
        let error = PeacemakrError(what: "failed to get my client ID", subsystem: .Persister, shouldSend: false)
        self.logHandler(error)
        return ""
      }
      
      return clientID!
    }
  }
  
  private var myPubKeyID: String {
    get {
      let pubKeyID: String? = self.persister.getData(self.dataPrefix + self.pubKeyIDTag)
      if pubKeyID == nil {
        let error = PeacemakrError(what: "failed to get my public key ID", subsystem: .Persister, shouldSend: false)
        self.logHandler(error)
        return ""
      }
      
      return pubKeyID!
    }
  }
  
  private func cryptoOnError(_ s: String) -> Void {
    let error = PeacemakrError(what: s, subsystem: .Crypto, shouldSend: true)
    self.log(error)
  }
  
  public func Register(completion: (@escaping (Error?) -> Void)) -> Bool {
    
    // Short-circuit if we've already registered
    if RegistrationSuccessful {
      completion(nil)
      return true
    }
    
    // Generate my keypair
    let myKey = PeacemakrKey(config: myKeyCfg, rand: rand)
    if myKey == nil {
      let error = PeacemakrError(what: "failed to generate my key pair", subsystem: .Crypto, shouldSend: true)
      self.logHandler(error)
      return false
    }
    
    // Store private key
    let priv = UnwrapCall(myKey!.toPem(is_priv: true), onError: self.cryptoOnError)
    if priv == nil {
      let error = PeacemakrError(what: "priv key to pem failed", subsystem: .Crypto, shouldSend: true)
      self.log(error)
      return false
    }
    var privPemData: Data? = nil
    priv?.withUnsafeBufferPointer({buf -> Void in
      privPemData = Data(buffer: buf)
    })
    if !self.persister.storeKey(privPemData!, keyID: self.privTag) {
      let error = PeacemakrError(what: "storing private key failed", subsystem: .Persister, shouldSend: true)
      self.log(error)
      return false
    }
    
    // Store public key
    let pub = UnwrapCall(myKey!.toPem(is_priv: false), onError: self.cryptoOnError)
    if pub == nil {
      let error = PeacemakrError(what: "pub key to pem failed", subsystem: .Crypto, shouldSend: true)
      self.log(error)
      return false
    }
    var pubPemData: Data? = nil
    pub?.withUnsafeBufferPointer({buf -> Void in
      pubPemData = Data(buffer: buf)
    })
    if !self.persister.storeKey(pubPemData!, keyID: self.pubTag) {
      let error = PeacemakrError(what: "Storing my public key failed", subsystem: .Persister, shouldSend: true)
      self.log(error)
      return false
    }
    
    // Call up to server and register myself
    let pubKeyToSend = PublicKey(_id: "", creationTime: Int(Date().timeIntervalSince1970), keyType: "rsa", encoding: "pem", key: String(cString: pub!))
    let registerClient = Client(_id: "", sdk: version, publicKey: pubKeyToSend)
    
    let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)
    requestBuilder.execute({ (client, error) in
      if error != nil {
        let e = PeacemakrError(what: "addClient failed with " + error.debugDescription, subsystem: .Network, shouldSend: false)
        self.log(e)
        completion(error)
        return
      }
      
      // Store the clientID and publicKeyID
      let clientID = client?.body?._id
      if clientID == nil {
        let e = PeacemakrError(what: "client ID returned from server was nil", subsystem: .Server, shouldSend: true)
        self.log(e)
        completion(NSError(domain: "no client ID", code: -1, userInfo: nil))
        return
      }
      if !self.persister.storeData(self.dataPrefix + self.clientIDTag, val: clientID) {
        let e = PeacemakrError(what: "could not store client ID", subsystem: .Persister, shouldSend: true)
        self.log(e)
        completion(NSError(domain: "could not store client ID", code: -2, userInfo: nil))
        return
      }
      
      let pubKeyID = client?.body?.publicKey._id
      if pubKeyID == nil {
        let e = PeacemakrError(what: "public key ID returned from server was nil", subsystem: .Server, shouldSend: true)
        self.log(e)
        completion(NSError(domain: "no public key ID", code: -3, userInfo: nil))
        return
      }
      if !self.persister.storeData(self.dataPrefix + self.pubKeyIDTag, val: pubKeyID) {
        let e = PeacemakrError(what: "could not store public key ID", subsystem: .Persister, shouldSend: true)
        self.log(e)
        completion(NSError(domain: "couldn't store public key ID", code: -4, userInfo: nil))
        return
      }
      
      completion(nil)
    })
    
    return true
  }
  
  public func Sync(completion: (@escaping (Error?) -> Void)) -> Void {
    self.syncOrgInfo { (err) in
      if err != nil {
        return completion(err)
      }
      
      self.syncCryptoConfig(completion: { (err) in
        if err != nil {
          return completion(err)
        }
        
        self.syncSymmetricKeys(completion: {
          return completion($0)
        })
      })
    }
  }
  
  public func ClearCache() -> Void {
    // TODO
  }
  
  private func storeKey(key: [UInt8], keyID: String) -> Bool {
    let tag = self.symmTagPrefix + keyID
    
    var keyData: Data? = nil
    key.withUnsafeBufferPointer{ buf -> Void in
      keyData = Data(buffer: buf)
    }
    
    return self.persister.storeKey(keyData!, keyID: tag)
  }
  
  private func getPublicKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig, completion: (@escaping (PeacemakrKey?) -> Void)) -> Void {
    if let keyBytes: String = self.persister.getData(self.dataPrefix + keyID) {
      return completion(PeacemakrKey(config: cfg, fileContents: keyBytes.cString(using: .utf8)!, is_priv: false))
    }
    
    let requestBuilder = KeyServiceAPI.getPublicKeyWithRequestBuilder(keyID: keyID)
    requestBuilder.execute({(key, error) in
      if error != nil {
        let e = PeacemakrError(what: "Attempted to get public key: " + error!.localizedDescription, subsystem: .Network, shouldSend: false)
        self.log(e)
        return completion(nil)
      }
      
      if let keyStr = key?.body?.key {
        if !self.persister.storeData(self.dataPrefix + keyID, val: keyStr) {
          let e = PeacemakrError(what: "Could not store public key: " + keyID, subsystem: .Persister, shouldSend: false)
          self.log(e)
          return completion(nil)
        }
        return completion(PeacemakrKey(config: cfg, fileContents: keyStr.cString(using: .utf8)!, is_priv: false))
      }
      
      return completion(nil)
    })
  }
  
  private func getLocalKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let tag = symmTagPrefix + keyID
    
    let keyData = self.persister.getKey(tag)
    if keyData == nil {
      let e = PeacemakrError(what: "Could not retreive key at: " + tag, subsystem: .Persister, shouldSend: false)
      self.log(e)
      return nil
    }
    
    if let keyBytes = keyData?.withUnsafeBytes({
      [UInt8](UnsafeBufferPointer(start: $0, count: keyData!.count))
    }) {
      return PeacemakrKey(config: cfg, bytes: keyBytes)
    }
    
    let e = PeacemakrError(what: "Unable to marshal key data into byte array", subsystem: .Swift, shouldSend: false)
    self.log(e)
    return nil
  }
  
  private func verifyMessage(plaintext: Plaintext, ciphertext: inout Ciphertext, verifyKey: PeacemakrKey, completion: (@escaping (Bool) -> Void)) {
    let verified = UnwrapCall(self.cryptoContext.Verify(senderKey: verifyKey, plaintext: plaintext, ciphertext: &ciphertext), onError: self.cryptoOnError)
    if verified == nil || verified == false {
      completion(false)
    }
    completion(true)
  }
  
  private func syncSymmetricKeys(completion: (@escaping (Error?) -> Void)) {
    let myPrivKey = getMyKey(priv: true)
    
    let finishKeyStorage = { (keyPlaintext: Plaintext, keyLen: Int, keyIDs: [String]) -> Void in
      guard let keyBytes = Data(base64Encoded: String(bytes: keyPlaintext.EncryptableData, encoding: .utf8)!) else {
        let e = PeacemakrError(what: "Invalid b64 key", subsystem: .Swift, shouldSend: false)
        self.log(e)
        completion(NSError(domain: "invalid b64 key", code: -15, userInfo: nil))
        return
      }
      
      for (i, keyID) in keyIDs.enumerated() {
        let thisKeyBytes = keyBytes[i*keyLen..<(i+1)*keyLen]
        if !self.storeKey(key: Array(thisKeyBytes), keyID: keyID) {
          let e = PeacemakrError(what: "Storing key failed for key: " + keyID, subsystem: .Persister, shouldSend: false)
          self.log(e)
          completion(NSError(domain: "Key storage failed", code: -16, userInfo: nil))
          return
        }
      }
      completion(nil)
    }
    
    let requestBuilder = KeyServiceAPI.getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: self.myClientID)
    requestBuilder.execute({(keys, error) in
      if error != nil {
        let e = PeacemakrError(what: "get encrypted keys failed with " + error!.localizedDescription, subsystem: .Network, shouldSend: false)
        self.log(e)
        completion(error)
        return
      }
      
      if keys == nil || keys?.body == nil || keys?.body?.count == 0 {
        let e = PeacemakrError(what: "no keys returned in get all encrypted keys request", subsystem: .Server, shouldSend: true)
        self.log(e)
        completion(NSError(domain: "No keys were returned", code: -10, userInfo: nil))
        return
      }
      
      // Now iterate over the keys in the message
      for key in keys!.body! {
        // Get the serialized ciphertext
        let serialized = key.packagedCiphertext.utf8
        
        // Grab the keyID from the ciphertext
        let storedKeyIDs = self.getKeyID(serialized: Array(serialized))
        if storedKeyIDs == nil {
          let e = PeacemakrError(what: "Unable to extract key IDs serialized key package", subsystem: .Server, shouldSend: true)
          self.log(e)
          completion(NSError(domain: "Unable to extract key IDs", code: -11, userInfo: nil))
          return
        }
        
        // Gotta get the singing key IDs
        let (_, signKeyID) = storedKeyIDs!
        let deserializedCfg = UnwrapCall(self.cryptoContext.Deserialize(Array(serialized)), onError: self.cryptoOnError)
        if deserializedCfg == nil {
          let e = PeacemakrError(what: "Unable to deserialize key package ciphertext", subsystem: .Crypto, shouldSend: false)
          self.log(e)
          completion(NSError(domain: "Unable to deserialize the key package", code: -12, userInfo: nil))
          return
        }
        var (deserialized, _) = deserializedCfg!
        
        // Decrypt the key
        let decryptResult = UnwrapCall(self.cryptoContext.Decrypt(key: myPrivKey!, ciphertext: deserialized), onError: self.cryptoOnError)
        if decryptResult == nil {
          let e = PeacemakrError(what: "Unable to decrypt key package ciphertext", subsystem: .Crypto, shouldSend: true)
          self.log(e)
          completion(NSError(domain: "Unable to decrypt the key package", code: -13, userInfo: nil))
          return
        }
        let (keyPlaintext, needVerify) = decryptResult!
        
        if needVerify {
          self.getPublicKeyByID(keyID: signKeyID, cfg: self.myKeyCfg, completion: { (pKey) in
            if pKey == nil { // already logged a message
              completion(NSError(domain: "Could not get signer public key", code: -14, userInfo: nil))
              return
            }
            self.verifyMessage(plaintext: keyPlaintext, ciphertext: &deserialized, verifyKey: pKey!, completion: {(verified) in
              if verified {
                finishKeyStorage(keyPlaintext, key.keyLength, key.keyIds)
              } else {
                let e = PeacemakrError(what: "unable to verify keyderiver message", subsystem: .Crypto, shouldSend: true)
                self.log(e)
                completion(NSError(domain: "Unable to verify message", code: -20, userInfo: nil))
              }
            })
          })
        } else {
          finishKeyStorage(keyPlaintext, key.keyLength, key.keyIds)
        }
      }
    })
  }
  
  // TODO: don't use the key if it's past its TTL
  private func getSymmKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig, completion: (@escaping (PeacemakrKey?, Error?) -> Void)) -> Void {
    let symmKey = getLocalKeyByID(keyID: keyID, cfg: cfg)
    if symmKey != nil {
      completion(symmKey, nil)
      return
    }
    
    // If we don't have the key already, re-sync and call the completion callback when we're done
    syncSymmetricKeys(completion: { (err) in
      if err != nil {
        completion(nil, err)
        return
      }
      
      let downloadedKey = self.getLocalKeyByID(keyID: keyID, cfg: cfg)
      if downloadedKey == nil {
        completion(nil, NSError(domain: "Could not get key " + keyID + " from storage after synchronizing keys", code: -17, userInfo: nil))
      }
      
      completion(downloadedKey, nil)
    })
  }
  
  private func getMyKey(priv: Bool) -> PeacemakrKey? {
    var tag: String
    if priv {
      tag = privTag
    } else {
      tag = pubTag
    }
    
    let keyData = self.persister.getKey(tag)
    if let keyBytes = keyData?.withUnsafeBytes({
      [Int8](UnsafeBufferPointer(start: $0, count: keyData!.count))
    }) {
      return PeacemakrKey(config: myKeyCfg, fileContents: keyBytes, is_priv: priv)
    }
    
    let e = PeacemakrError(what: "unable to get my key (public/private) from keychain", subsystem: .Persister, shouldSend: false)
    self.log(e)
    return nil
  }
  
  // Stores org ID and crypto config ID
  private func syncOrgInfo(completion: (@escaping (Error?) -> Void)) -> Void {
    let requestBuilder = OrgAPI.getOrganizationFromAPIKeyWithRequestBuilder(apikey: self.apiKey)
    requestBuilder.execute { (response, err) in
      if err != nil {
        let e = PeacemakrError(what: "Trying to get org from API Key: " + err!.localizedDescription, subsystem: .Network, shouldSend: false)
        self.log(e)
        completion(err)
        return
      }
      
      let orgID = response?.body?._id
      if !self.persister.storeData(self.dataPrefix + "OrgID", val: orgID!) {
        let e = PeacemakrError(what: "Unable to store OrgID", subsystem: .Server, shouldSend: true)
        self.log(e)
        completion(NSError(domain: "Unable to store org ID", code: -30, userInfo: nil))
        return
      }
      
      let cryptoConfigID = response?.body?.cryptoConfigId
      if !self.persister.storeData(self.dataPrefix + "CryptoConfigID", val: cryptoConfigID!) {
        let e = PeacemakrError(what: "Unable to store CryptoConfigID", subsystem: .Persister, shouldSend: false)
        self.log(e)
        completion(NSError(domain: "Unable to store crypto config ID", code: -31, userInfo: nil))
        return
      }
      
      completion(nil)
    }
  }
  
  private func syncCryptoConfig(completion: (@escaping (Error?) -> Void)) -> Void {
    let cryptoConfigID: String? = self.persister.getData(self.dataPrefix + "CryptoConfigID")
    
    let requestBuilder = CryptoConfigAPI.getCryptoConfigWithRequestBuilder(cryptoConfigId: cryptoConfigID!)
    requestBuilder.execute { (response, err) in
      if err != nil {
        let e = PeacemakrError(what: "Trying to get the CryptoConfig: " + err!.localizedDescription, subsystem: .Network, shouldSend: false)
        self.log(e)
        completion(err)
        return
      }
      
      if response?.body == nil {
        let e = PeacemakrError(what: "Response body was nil", subsystem: .Server, shouldSend: true)
        self.log(e)
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }
      
      if !self.persister.storeData(self.dataPrefix + "UseDomainSelectorScheme", val: response?.body?.symmetricKeyUseDomainSelectorScheme) {
        let e = PeacemakrError(what: "Failed to store use domain selector scheme", subsystem: .Persister, shouldSend: false)
        self.log(e)
        completion(NSError(domain: "failed to store use domain selector scheme", code: -37, userInfo: nil))
      }
      
      let data = try? JSONEncoder().encode(response?.body?.symmetricKeyUseDomains)
      if data == nil {
        completion(NSError(domain: "Failed to json encode the use domains", code: -36, userInfo: nil))
        return
      }
      
      if !self.persister.storeData(self.dataPrefix + "UseDomains", val: data!) {
        let e = PeacemakrError(what: "Failed to store use domains", subsystem: .Persister, shouldSend: false)
        self.log(e)
        completion(NSError(domain: "failed to store use domains", code: -35, userInfo: nil))
      }
      
      completion(nil)
    }
  }
  
  private func selectKey(useDomainID: String) -> (String, CoreCrypto.CryptoConfig)? {
    // Use the string, if it's empty then just use the first one
    let encodedUseDomains: Data? = self.persister.getData(self.dataPrefix + "UseDomains")
    if encodedUseDomains == nil {
      // If the enocded use domains are nil, it's likely that we were sent an empty list from the server
      let e = PeacemakrError(what: "Persisted use domains were nil", subsystem: .Server, shouldSend: true)
      self.log(e)
      return nil
    }
    
//    let useDomainSelector: String? = self.persister.getData(self.dataPrefix + "UseDomainSelectorScheme")
//    if useDomainSelector == nil {
//      let e = PeacemakrError(what: "Persisted use domain selector scheme was nil")
//      return nil
//    }
    
    let useDomains = try? JSONDecoder().decode([SymmetricKeyUseDomain].self, from: encodedUseDomains!)
    
    // Use a random one at first
    var useDomainToUse = useDomains?.randomElement()
    if !useDomainID.isEmpty {
      for domain in useDomains! {
        if domain._id == useDomainID {
          useDomainToUse = domain
          break
        }
      }
    }
    
    let encryptionKeys = useDomainToUse?.encryptionKeyIds
    if encryptionKeys == nil {
      let e = PeacemakrError(what: "Invalid use domain, no key IDs contained within", subsystem: .Server, shouldSend: true)
      self.log(e)
      return nil
    }
    
    var keyCfg = CoreCrypto.CryptoConfig(mode: .SYMMETRIC, symm_cipher: .CHACHA20_POLY1305, asymm_cipher: .NONE, digest: .SHA3_512)
    if useDomainToUse?.symmetricKeyEncryptionAlg == "AESGCM" {
      keyCfg = CoreCrypto.CryptoConfig(mode: .SYMMETRIC, symm_cipher: .AES_256_GCM, asymm_cipher: .NONE, digest: .SHA3_512)
    }
    
    let encryptionKeyID = encryptionKeys?.randomElement()
    if encryptionKeyID == nil {
      // This means something ahs gone horribly wrong in the encryption key IDs
      let e = PeacemakrError(what: "Invalid encryption key ID", subsystem: .Server, shouldSend: true)
      self.log(e)
      return nil
    }
    
    return (encryptionKeyID!, keyCfg)
  }
  
  // This edits the plaintext to add the key ID to the message before it gets encrypted and sent out
  private func getEncryptionKey(useDomainID: String) -> (String, PeacemakrKey)? {
      
    let keyIDandCfg = self.selectKey(useDomainID: useDomainID)
    if keyIDandCfg == nil {
      // Already logged inside the function
      return nil
    }
    
    let jsonObject: [String: String] = ["cryptoKeyID": keyIDandCfg!.0, "senderKeyID": self.myPubKeyID]
    let aadJSON = try? JSONSerialization.data(withJSONObject: jsonObject, options: [])
    if aadJSON == nil {
      let e = PeacemakrError(what: "Failed to serialize the key IDs to json", subsystem: .Swift, shouldSend: false)
      self.log(e)
      return nil
    }
    let messageAAD = String(data: aadJSON!, encoding: .utf8)
    if messageAAD == nil {
      let e = PeacemakrError(what: "Failed to marshal the json AAD to a string", subsystem: .Swift, shouldSend: false)
      self.log(e)
      return nil
    }
    
    let keyToUse = self.getLocalKeyByID(keyID: keyIDandCfg!.0, cfg: keyIDandCfg!.1)
    if keyToUse == nil {
      let e = PeacemakrError(what: "Unable to get key with ID " + keyIDandCfg!.0, subsystem: .Persister, shouldSend: false)
      self.log(e)
      return nil
    }
    
    return (messageAAD!, keyToUse!)
  }
  
  /**
   Returns an encrypted and base64 serialized blob that contains \p plaintext.
   Throws an error on failure of encryption or serialization.
   */
  public func Encrypt(_ plaintext: Encryptable, useDomainID: String? = nil) -> ([UInt8], Error?) {
    let aadAndKey = self.getEncryptionKey(useDomainID: useDomainID ?? "")
    if aadAndKey == nil {
      return ([UInt8](), NSError(domain: "Unable to get the encryption key", code: -101, userInfo: nil))
    }
    let p = Plaintext(data: plaintext.serializedValue, aad: [UInt8](aadAndKey!.0.utf8))
    
    var encrypted = UnwrapCall(self.cryptoContext.Encrypt(
      key: aadAndKey!.1,
      plaintext: p,
      rand: self.rand
    ), onError: self.cryptoOnError)
    if encrypted == nil {
      let e = PeacemakrError(what: "Encryption failed", subsystem: .Crypto, shouldSend: true)
      self.log(e)
      return ([UInt8](), NSError(domain: "Encryption failed", code: -103, userInfo: nil))
    }
    
    let signKey = self.getMyKey(priv: true)
    if signKey == nil {
      let e = PeacemakrError(what: "Unable to get my private key", subsystem: .Persister, shouldSend: true)
      self.log(e)
      return ([UInt8](), NSError(domain: "Unable to get my private key", code: -104, userInfo: nil))
    }
    
    self.cryptoContext.Sign(senderKey: signKey!, plaintext: p, ciphertext: &encrypted!)
    
    let serialized = UnwrapCall(self.cryptoContext.Serialize(encrypted!), onError: self.cryptoOnError)
    if serialized == nil {
      let e = PeacemakrError(what: "Serialization failed", subsystem: .Crypto, shouldSend: true)
      self.log(e)
      return ([UInt8](), NSError(domain: "Serialization failed", code: -105, userInfo: nil))
    }
    
    return (serialized!, nil)
  }
  
  private func getKeyID(serialized: [UInt8]) -> (String, String)? {
    let serializedAAD = UnwrapCall(cryptoContext.ExtractUnverifiedAAD(serialized), onError: self.cryptoOnError)
    if serializedAAD == nil {
      return nil
    }
    
    let aadDict = try? JSONSerialization.jsonObject(with: Data(bytes: serializedAAD!.AuthenticatableData), options: [])
    if aadDict == nil {
      let e = PeacemakrError(what: "json deserialization of AAD failed", subsystem: .Swift, shouldSend: true)
      self.log(e)
      return nil
    }
    
    if let aad = aadDict as? [String: Any] {
      let cryptoKeyID = aad["cryptoKeyID"] as? String
      let senderKeyID = aad["senderKeyID"] as? String
      if cryptoKeyID != nil && cryptoKeyID! == "" {
        return ("", senderKeyID!)
      }
      
      return (cryptoKeyID!, senderKeyID!)
    }
    
    return ("", "")
    
  }
  
  /**
   Deserializes and decrypts \p serialized and stores the output into \p dest.
   Throws an error on failure of deserialization or decryption.
   */
  public func Decrypt(_ serialized: [UInt8], dest: Encryptable, completion: (@escaping (Encryptable?, Error?) -> Void)) -> Bool {
    let keyIDs = getKeyID(serialized: serialized)
    if keyIDs == nil {
      let e = PeacemakrError(what: "Unable to parse key IDs from message", subsystem: .Crypto, shouldSend: false)
      self.log(e)
      return false
    }
    
    let (keyID, signKeyID) = keyIDs!
    let deserializedCfg = UnwrapCall(cryptoContext.Deserialize(serialized), onError: self.cryptoOnError)
    if deserializedCfg == nil {
      let e = PeacemakrError(what: "Unable to deserialize encrypted message", subsystem: .Crypto, shouldSend: false)
      self.log(e)
      return false
    }
    var (deserialized, cfg) = deserializedCfg!
    
    // Get the key specified by the message
    getSymmKeyByID(keyID: keyID, cfg: cfg, completion: { (key, err) in
      var dest = dest
      if err != nil {
        let e = PeacemakrError(what: "Trying to get the symmetric key: " + err!.localizedDescription, subsystem: .Network, shouldSend: false)
        self.log(e)
        completion(nil, err)
      }
      if key == nil {
        let e = PeacemakrError(what: "Unable to get symmetric key for decrypting the messaage", subsystem: .Server, shouldSend: true)
        self.log(e)
        completion(nil, NSError(domain: "Unable to get symmetric decrypt key", code: -106, userInfo: nil))
        return
      }
      
      // Then decrypt
      let decryptResult = UnwrapCall(self.cryptoContext.Decrypt(key: key!, ciphertext: deserialized), onError: self.cryptoOnError)
      if decryptResult == nil {
        let e = PeacemakrError(what: "Decryption failed - decrypt key ID: " + keyID, subsystem: .Crypto, shouldSend: true)
        self.log(e)
        completion(nil, NSError(domain: "Decryption failed", code: -107, userInfo: nil))
        return
      }
      let (outPlaintext, needsVerify) = decryptResult!
      // And verify (which is another callback)
      if needsVerify {
        self.getPublicKeyByID(keyID: signKeyID, cfg: self.myKeyCfg, completion: { (verifyKey) in
          if verifyKey == nil {
            completion(nil, NSError(domain: "Verification failed", code: -113, userInfo: nil))
            return
          }
          self.verifyMessage(plaintext: outPlaintext, ciphertext: &deserialized, verifyKey: verifyKey!, completion: { (verified) in
            if !verified {
              let e = PeacemakrError(what: "Verification failed - public key ID: " + signKeyID, subsystem: .Crypto, shouldSend: true)
              self.log(e)
              completion(nil, NSError(domain: "Verification failed", code: -108, userInfo: nil))
              return
            }
            dest.serializedValue = outPlaintext.EncryptableData
            completion(dest, nil)
          })
        })
      } else {
        dest.serializedValue = outPlaintext.EncryptableData
        completion(dest, nil)
      }
    })
    
    return true
  }
  
}
