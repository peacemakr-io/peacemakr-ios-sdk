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
  private let version = "0.0.1"
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
  
  private let dataPrefix = "io.peacemakr.client."
  private let privTag = "io.peacemakr.client.private"
  private let pubTag = "io.peacemakr.client.public"
  // symmetric keys start with this prefix and append the key ID onto it
  private let symmTagPrefix = "io.peacemakr.client.symmetric."
  
  private let clientIDTag = "ClientID"
  private let pubKeyIDTag = "PubKeyID"
  
  private let persister: Persister
  
  public init?(apiKey: String, logHandler: @escaping (String)->Void) {
    self.apiKey = apiKey
    self.logHandler = logHandler
    
    let cc = CryptoContext()
    cryptoContext = cc!
    rand = PeacemakrRandomDevice()
    
    self.persister = DefaultPersister(logHandler: self.logHandler)
    
    if cc == nil {
      self.log("Unable to init CryptoContext")
      return nil
    }
    
//    SwaggerClientAPI.basePath = SwaggerClientAPI.basePath.replacingOccurrences(of: "http", with: "https")
    SwaggerClientAPI.basePath = "http://localhost:8080/api/v1"
    SwaggerClientAPI.customHeaders = ["Authorization": self.apiKey]
  }
  
  private func log(_ s: String) -> Void {
    let logStr = s + " - SDK Version: iOS-" + self.version
    
    if self.RegistrationSuccessful {
      let logEvent = Log(clientId: getMyClientID(), event: logStr)
      
      let requestBuilder = PhoneHomeAPI.logPostWithRequestBuilder(log: logEvent)
      requestBuilder.execute({(response, error) in
        if error != nil {
          self.logHandler("phonehome request failed")
        }
      })
    }
    
    // Log whether or not the request succeeds
    self.logHandler(logStr)
  }
  
  public var RegistrationSuccessful: Bool {
    get {
      return self.persister.hasData(self.dataPrefix + self.clientIDTag) && self.persister.hasData(self.dataPrefix + self.pubKeyIDTag)
    }
  }
  
  public func Register(completion: (@escaping (Error?) -> Void)) -> Bool {
    
    // Generate my keypair
    let myKey = PeacemakrKey(config: myKeyCfg, rand: rand)
    if myKey == nil {
      self.log("Keygen failed")
      return false
    }
    
    // Store private key
    let priv = UnwrapCall(myKey!.toPem(is_priv: true), onError: self.log)
    if priv == nil {
      self.log("priv key to pem failed")
      return false
    }
    var privPemData: Data? = nil
    priv?.withUnsafeBufferPointer({buf -> Void in
      privPemData = Data(buffer: buf)
    })
    if !self.persister.storeKey(privPemData!, keyID: self.privTag) {
      self.log("Storing my private key failed")
      return false
    }
    
    // Store public key
    let pub = UnwrapCall(myKey!.toPem(is_priv: false), onError: self.log)
    if pub == nil {
      self.log("pub key to pem failed")
      return false
    }
    var pubPemData: Data? = nil
    pub?.withUnsafeBufferPointer({buf -> Void in
      pubPemData = Data(buffer: buf)
    })
    if !self.persister.storeKey(pubPemData!, keyID: self.pubTag) {
      self.log("Storing my public key failed")
      return false
    }
    
    // Call up to server and register myself
    let pubKeyToSend = PublicKey(_id: "", creationTime: Int(Date().timeIntervalSince1970), keyType: "rsa", encoding: "pem", key: String(cString: pub!))
    let registerClient = Client(_id: "", sdk: version, publicKey: pubKeyToSend)
    
    let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)
    requestBuilder.execute({ (client, error) in
      self.logHandler("Register request completed")
      if error != nil {
        self.log("addClient failed with " + error.debugDescription)
        completion(error)
        return
      }
      
      // Store the clientID and publicKeyID
      let clientID = client?.body?._id
      if clientID == nil {
        self.log("Client ID returned was nil")
        completion(NSError(domain: "no client ID", code: -1, userInfo: nil))
        return
      }
      if !self.persister.storeData(self.dataPrefix + self.clientIDTag, val: clientID) {
        self.log("couldn't store my client ID")
        completion(NSError(domain: "could not store client ID", code: -2, userInfo: nil))
        return
      }
      
      let pubKeyID = client?.body?.publicKey._id
      if pubKeyID == nil {
        self.log("Public key ID returned was nil")
        completion(NSError(domain: "no public key ID", code: -3, userInfo: nil))
        return
      }
      if !self.persister.storeData(self.dataPrefix + self.pubKeyIDTag, val: pubKeyID) {
        self.log("couldn't store my public key ID")
        completion(NSError(domain: "couldn't store public key ID", code: -4, userInfo: nil))
        return
      }
      
      self.log("Registered new iOS client: " + self.getMyClientID())
      completion(nil)
    })
    
    return true
  }
  
  private func getMyClientID() -> String {
    let clientID: String? = self.persister.getData(self.dataPrefix + self.clientIDTag)
    if clientID == nil {
      self.logHandler("failed to get my client ID")
      return ""
    }
    
    return clientID!
  }
  
  public func Sync(completion: (@escaping (Error?) -> Void)) -> Void {
    self.syncOrgInfo { (err) in
      if err != nil {
        completion(err)
      }
      
      self.syncCryptoConfig(completion: { (err) in
        if err != nil {
          completion(err)
        }
        
        self.syncSymmetricKeys(completion: {completion($0)})
      })
    }
  }
  
  private func storeKey(key: [UInt8], keyID: [UInt8]) -> Bool {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      self.log("Could not serialize keyID to string")
      return false
    }
    let tag = self.symmTagPrefix + keyIDStr!
    
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
        self.log("Attempted to get public key: " + error!.localizedDescription)
        return completion(nil)
      }
      
      if let keyStr = key?.body?.key {
        if !self.persister.storeData(self.dataPrefix + keyID, val: keyStr) {
          self.log("Unable to store returned key: " + keyID)
        }
        return completion(PeacemakrKey(config: cfg, fileContents: keyStr.cString(using: .utf8)!, is_priv: false))
      }
      
      self.log("Attempted to get public key, and the response was empty")
      return completion(nil)
    })
  }
  
  private func getLocalKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let tag = symmTagPrefix + keyID
    
    let keyData = self.persister.getKey(tag)
    if keyData == nil {
      self.log("Could not retreive key at: " + tag)
      return nil
    }
    
    if let keyBytes = keyData?.withUnsafeBytes({
      [UInt8](UnsafeBufferPointer(start: $0, count: keyData!.count))
    }) {
      return PeacemakrKey(config: cfg, bytes: keyBytes)
    }
    
    self.log("Unable to marshal key data into byte array")
    return nil
  }
  
  private func verifyMessage(plaintext: Plaintext, ciphertext: inout Ciphertext, verifyKey: PeacemakrKey, completion: (@escaping (Bool) -> Void)) {
    let verified = UnwrapCall(self.cryptoContext.Verify(senderKey: verifyKey, plaintext: plaintext, ciphertext: &ciphertext), onError: self.log)
    if verified == nil || verified == false {
      completion(false)
    }
    completion(true)
  }
  
  private func syncSymmetricKeys(completion: (@escaping (Error?) -> Void)) {
    let myClientID = getMyClientID()
    let myPrivKey = getMyKey(priv: true)
    
    let finishKeyStorage = { (keyPlaintext: Plaintext, keyLen: Int, keyIDs: [String]) -> Void in
      self.log("Storing keys: " + keyIDs.joined(separator: ", "))
      
      guard let keyBytes = Data(base64Encoded: String(bytes: keyPlaintext.EncryptableData, encoding: .utf8)!) else {
        self.log("Invalid b64 key")
        completion(NSError(domain: "invalid b64 key", code: -15, userInfo: nil))
        return
      }
      
      for (i, keyID) in keyIDs.enumerated() {
        let thisKeyBytes = keyBytes[i*keyLen..<(i+1)*keyLen]
        if !self.storeKey(key: Array(thisKeyBytes), keyID: Array(keyID.utf8)) {
          self.log("Storing key failed for key: " + keyID)
          completion(NSError(domain: "Key storage failed", code: -16, userInfo: nil))
          return
        }
      }
      completion(nil)
    }
    
    let requestBuilder = KeyServiceAPI.getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: myClientID)
    requestBuilder.execute({(keys, error) in
      if error != nil {
        self.log("get encrypted keys failed with " + error!.localizedDescription)
        completion(error)
        return
      }
      
      if keys == nil || keys?.body == nil || keys?.body?.count == 0 {
        self.log("no keys returned in get all encrypted keys request")
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
          self.log("Unable to extract key IDs serialized key package")
          completion(NSError(domain: "Unable to extract key IDs", code: -11, userInfo: nil))
          return
        }
        
        // Gotta get the singing key IDs
        let (_, signKeyID) = storedKeyIDs!
        let deserializedCfg = UnwrapCall(self.cryptoContext.Deserialize(Array(serialized)), onError: self.log)
        if deserializedCfg == nil {
          self.log("Unable to deserialize key package ciphertext")
          completion(NSError(domain: "Unable to deserialize the key package", code: -12, userInfo: nil))
          return
        }
        var (deserialized, _) = deserializedCfg!
        
        // Decrypt the key
        let decryptResult = UnwrapCall(self.cryptoContext.Decrypt(key: myPrivKey!, ciphertext: deserialized), onError: self.log)
        if decryptResult == nil {
          self.log("Unable to decrypt key package ciphertext")
          completion(NSError(domain: "Unable to decrypt the key package", code: -13, userInfo: nil))
          return
        }
        let (keyPlaintext, needVerify) = decryptResult!
        
        if needVerify {
          self.getPublicKeyByID(keyID: signKeyID, cfg: self.myKeyCfg, completion: { (pKey) in
            if pKey == nil {
              self.log("Public key: " + signKeyID + " could not be gotten")
              completion(NSError(domain: "Could not get signer public key", code: -14, userInfo: nil))
              return
            }
            self.verifyMessage(plaintext: keyPlaintext, ciphertext: &deserialized, verifyKey: pKey!, completion: {(verified) in
              if verified {
                finishKeyStorage(keyPlaintext, key.keyLength, key.keyIds)
              } else {
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
    
    self.log("unable to get my key (public/private) from keychain")
    return nil
  }
  
  private func getMyPublicKeyID() -> String {
    let pubKeyID: String? = self.persister.getData(self.dataPrefix + self.pubKeyIDTag)
    if pubKeyID == nil {
      self.log("failed to get my public key ID from the filesystem")
      return ""
    }
    
    return pubKeyID!
  }
  
  // Stores org ID and crypto config ID
  private func syncOrgInfo(completion: (@escaping (Error?) -> Void)) -> Void {
    let requestBuilder = OrgAPI.getOrganizationFromAPIKeyWithRequestBuilder(apikey: self.apiKey)
    requestBuilder.execute { (response, err) in
      if err != nil {
        self.log("Trying to get org from API Key: " + err!.localizedDescription)
        completion(err)
        return
      }
      
      let orgID = response?.body?._id
      if !self.persister.storeData(self.dataPrefix + "OrgID", val: orgID!) {
        self.log("Unable to store OrgID")
        completion(NSError(domain: "Unable to store org ID", code: -30, userInfo: nil))
        return
      }
      
      let cryptoConfigID = response?.body?.cryptoConfigId
      if !self.persister.storeData(self.dataPrefix + "CryptoConfigID", val: cryptoConfigID!) {
        self.log("Unable to store CryptoConfigID")
        completion(NSError(domain: "Unable to store crypto config ID", code: -31, userInfo: nil))
        return
      }
      
      self.log("got orgID " + orgID! + " and cryptoConfigID " + cryptoConfigID!)
      
      completion(nil)
    }
  }
  
  private func syncCryptoConfig(completion: (@escaping (Error?) -> Void)) -> Void {
    let cryptoConfigID: String? = self.persister.getData(self.dataPrefix + "CryptoConfigID")
    
    let requestBuilder = CryptoConfigAPI.getCryptoConfigWithRequestBuilder(cryptoConfigId: cryptoConfigID!)
    requestBuilder.execute { (response, err) in
      if err != nil {
        self.log("Trying to get the CryptoConfig: " + err!.localizedDescription)
        completion(err)
        return
      }
      
      if response?.body == nil {
        self.log("Response body was nil")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }
      
      if !self.persister.storeData(self.dataPrefix + "UseDomainSelectorScheme", val: response?.body?.symmetricKeyUseDomainSelectorScheme) {
        self.log("Failed to store use domain selector scheme")
        completion(NSError(domain: "failed to store use domain selector scheme", code: -37, userInfo: nil))
      }
      
      let data = try? JSONEncoder().encode(response?.body?.symmetricKeyUseDomains)
      if data == nil {
        completion(NSError(domain: "Failed to json encode the use domains", code: -36, userInfo: nil))
        return
      }
      
      if !self.persister.storeData(self.dataPrefix + "UseDomains", val: data!) {
        self.log("Failed to store use domains")
        completion(NSError(domain: "failed to store use domains", code: -35, userInfo: nil))
      }
      
      self.log("Synchronized the crypto config")
      completion(nil)
    }
  }
  
  private func selectKey(useDomainID: String) -> (String, CoreCrypto.CryptoConfig)? {
    // Use the string, if it's empty then just use the first one
    let encodedUseDomains: Data? = self.persister.getData(self.dataPrefix + "UseDomains")
    if encodedUseDomains == nil {
      self.log("Persisted use domains were nil")
      return nil
    }
    
//    let useDomainSelector: String? = self.persister.getData(self.dataPrefix + "UseDomainSelectorScheme")
//    if useDomainSelector == nil {
//      self.log("Persisted use domain selector scheme was nil")
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
      self.log("Invalid use domain, no key IDs contained within")
      return nil
    }
    
    let encryptionKeyID = encryptionKeys?.randomElement()
    var keyCfg = CoreCrypto.CryptoConfig(mode: .SYMMETRIC, symm_cipher: .CHACHA20_POLY1305, asymm_cipher: .NONE, digest: .SHA3_512)
    if useDomainToUse?.symmetricKeyEncryptionAlg == "AESGCM" {
      keyCfg = CoreCrypto.CryptoConfig(mode: .SYMMETRIC, symm_cipher: .AES_256_GCM, asymm_cipher: .NONE, digest: .SHA3_512)
    }
    
    if encryptionKeyID == nil {
      self.log("Invalid encryption key ID")
      return nil
    }
    
    return (encryptionKeyID!, keyCfg)
  }
  
  // This edits the plaintext to add the key ID to the message before it gets encrypted and sent out
  private func getEncryptionKey(useDomainID: String) -> (String, PeacemakrKey)? {
      
    let keyIDandCfg = self.selectKey(useDomainID: useDomainID)
    if keyIDandCfg == nil {
      self.log("Unable to select a key")
      return nil
    }
    
    let myPubKeyID = self.getMyPublicKeyID()
    
    let jsonObject: [String: String] = ["cryptoKeyID": keyIDandCfg!.0, "senderKeyID": myPubKeyID]
    let aadJSON = try? JSONSerialization.data(withJSONObject: jsonObject, options: [])
    if aadJSON == nil {
      self.log("Failed to serialize the key IDs to json")
      return nil
    }
    let messageAAD = String(data: aadJSON!, encoding: .utf8)
    if messageAAD == nil {
      self.log("Failed to marshal the json AAD to a string")
      return nil
    }
    
    let keyToUse = self.getLocalKeyByID(keyID: keyIDandCfg!.0, cfg: keyIDandCfg!.1)
    if keyToUse == nil {
      self.log("Unable to get key with ID " + keyIDandCfg!.0)
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
    ), onError: self.log)
    if encrypted == nil {
      self.log("Encryption failed")
      return ([UInt8](), NSError(domain: "Encryption failed", code: -103, userInfo: nil))
    }
    
    let signKey = self.getMyKey(priv: true)
    if signKey == nil {
      self.log("Unable to get my private key")
      return ([UInt8](), NSError(domain: "Unable to get my private key", code: -104, userInfo: nil))
    }
    
    self.cryptoContext.Sign(senderKey: signKey!, plaintext: p, ciphertext: &encrypted!)
    
    let serialized = UnwrapCall(self.cryptoContext.Serialize(encrypted!), onError: self.log)
    if serialized == nil {
      self.log("Serialization failed")
      return ([UInt8](), NSError(domain: "Serialization failed", code: -105, userInfo: nil))
    }
    
    return (serialized!, nil)
  }
  
  private func getKeyID(serialized: [UInt8]) -> (String, String)? {
    let serializedAAD = UnwrapCall(cryptoContext.ExtractUnverifiedAAD(serialized), onError: self.log)
    if serializedAAD == nil {
      return nil
    }
    
    let aadDict = try? JSONSerialization.jsonObject(with: Data(bytes: serializedAAD!.AuthenticatableData), options: [])
    if aadDict == nil {
      self.log("json deserialization of AAD failed")
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
  public func Decrypt(_ serialized: [UInt8], dest: Encryptable, completion: (@escaping (Encryptable) -> Void)) -> Bool {
    let keyIDs = getKeyID(serialized: serialized)
    if keyIDs == nil {
      self.log("Unable to parse key IDs from message")
      return false
    }
    
    let (keyID, signKeyID) = keyIDs!
    let deserializedCfg = UnwrapCall(cryptoContext.Deserialize(serialized), onError: self.log)
    if deserializedCfg == nil {
      self.log("Unable to deserialize encrypted message")
      return false
    }
    var (deserialized, cfg) = deserializedCfg!
    
    // Get the key specified by the message
    getSymmKeyByID(keyID: keyID, cfg: cfg, completion: { (key, err) in
      var dest = dest
      if err != nil {
        self.log("Trying to get the symmetric key: " + err!.localizedDescription)
        dest.onError(error: err!)
        completion(dest)
      }
      if key == nil {
        self.log("Unable to get symmetric key for decrypting the messaage")
        dest.onError(error: NSError(domain: "Unable to get symmetric decrypt key", code: -106, userInfo: nil))
        completion(dest)
        return
      }
      
      // Then decrypt
      let decryptResult = UnwrapCall(self.cryptoContext.Decrypt(key: key!, ciphertext: deserialized), onError: self.log)
      if decryptResult == nil {
        self.log("Decryption failed")
        dest.onError(error: NSError(domain: "Decryption failed", code: -107, userInfo: nil))
        completion(dest)
        return
      }
      let (outPlaintext, needsVerify) = decryptResult!
      // And verify (which is another callback)
      if needsVerify {
        self.getPublicKeyByID(keyID: signKeyID, cfg: self.myKeyCfg, completion: { (verifyKey) in
          self.verifyMessage(plaintext: outPlaintext, ciphertext: &deserialized, verifyKey: verifyKey!, completion: { (verified) in
            if !verified {
              self.log("Verification failed")
              dest.onError(error: NSError(domain: "Verification failed", code: -108, userInfo: nil))
              completion(dest)
              return
            }
            dest.serializedValue = outPlaintext.EncryptableData
            completion(dest)
          })
        })
      } else {
        dest.serializedValue = outPlaintext.EncryptableData
        completion(dest)
      }
    })
    
    return true
  }
  
}
