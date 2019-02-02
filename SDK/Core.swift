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
      
      self.log("Registered new iOS client: \(self.RegistrationSuccessful)")
      completion(nil)
    })
    
    return true
  }
  
  private func getMyClientID() -> String {
    let clientID: String? = self.persister.getData(self.dataPrefix + self.pubKeyIDTag)
    if clientID == nil {
      self.logHandler("failed to get my client ID")
      return ""
    }
    
    return clientID!
  }
  
  public func PreLoad() -> Bool {
    self.log("Unimplemented")
    return false
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
  
  // Key creation can fail
  private func getPublicKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig, completion: (@escaping (PeacemakrKey?) -> Void)) -> Void {
    
    if let keyBytes: String = self.persister.getData(self.dataPrefix + String(bytes: keyID, encoding: .utf8)!) {
      return keyBytes.withCString {
        completion(PeacemakrKey(config: cfg, fileContents: [CChar](UnsafeBufferPointer(start: $0, count: keyBytes.count)), is_priv: false))
      }
    }
    
    let requestBuilder = KeyServiceAPI.getPublicKeyWithRequestBuilder(keyID: String(bytes: keyID, encoding: .utf8)!)
    requestBuilder.execute({(key, error) in
      let keyStr = key?.body?.key ?? ""
      let keyIDStr = String(bytes: keyID, encoding: .utf8) ?? "unknown-key-id"
      if !self.persister.storeData(self.dataPrefix + keyIDStr, val: keyStr) {
        self.log("Unable to store returned key: " + keyIDStr)
      }
      keyStr.withCString {
        completion(PeacemakrKey(config: cfg, fileContents: [CChar](UnsafeBufferPointer(start: $0, count: keyStr.count)), is_priv: false))
      }
    })
  }
  
  private func getLocalKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      self.log("Could not marshal keyID to string")
      return nil
    }
    let tag = symmTagPrefix + keyIDStr!
    
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
    }
    
    let requestBuilder = KeyServiceAPI.getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: myClientID)
    requestBuilder.execute({(keys, error) in
      if error != nil {
        self.log("get encrypted keys failed")
        completion(error)
        return
      }
      
      if keys == nil || keys?.body == nil {
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
              self.log("Public key: " + String(bytes: signKeyID, encoding: .utf8)! + " could not be gotten")
              completion(NSError(domain: "Could not get signer public key", code: -14, userInfo: nil))
            }
            self.verifyMessage(plaintext: keyPlaintext, ciphertext: &deserialized, verifyKey: pKey!, completion: {(verified) in
              if verified {
                finishKeyStorage(keyPlaintext, key.keyLength, key.keyIds)
              }
            })
          })
        } else {
          finishKeyStorage(keyPlaintext, key.keyLength, key.keyIds)
        }
      }
    })
  }
  
  private func getSymmKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig, completion: (@escaping (PeacemakrKey?, Error?) -> Void)) -> Void {
    let symmKey = getLocalKeyByID(keyID: keyID, cfg: cfg)
    if symmKey != nil {
      completion(symmKey, nil)
      return
    }
    
    // If we don't have the key already, re-sync and call the completion callback when we're done
    syncSymmetricKeys(completion: { (err) in
      if err != nil {
        self.log(err!.localizedDescription)
        return
      }
      
      let downloadedKey = self.getLocalKeyByID(keyID: keyID, cfg: cfg)
      if downloadedKey == nil {
        completion(nil, NSError(domain: "Could not get key " + String(bytes: keyID, encoding: .utf8)! + " from storage after synchronizing keys", code: -17, userInfo: nil))
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
    let pubKeyID: String? = self.persister.getData("pubKeyID")
    if pubKeyID == nil {
      self.log("failed to get my public key ID from the filesystem")
      return ""
    }
    
    return pubKeyID!
  }
  
  private func selectKey(completion: (@escaping ([UInt8], CoreCrypto.CryptoConfig) -> Void)) -> Void {
    // TODO
  }
  
  // This edits the plaintext to add the key ID to the message before it gets encrypted and sent out
  private func getEncryptionKey(plaintext: Plaintext, completion: (@escaping (Plaintext?, PeacemakrKey?, Error?) -> Void)) -> Void {
    selectKey { (keyID, cfg) in
      let myPubKeyID = self.getMyPublicKeyID()
      self.getSymmKeyByID(keyID: keyID, cfg: cfg, completion: { (peacemakrKey, err) in
        if err != nil {
          completion(nil, nil, err)
          return
        }
        
        let jsonObject: [String: [UInt8]] = ["cryptoKeyID": keyID, "senderKeyID": [UInt8](myPubKeyID.utf8)]
        let aadJSON = try? JSONSerialization.data(withJSONObject: jsonObject, options: [])
        if aadJSON == nil {
          self.log("Failed to serialize the key IDs to json")
          return
        }
        let messageAAD = String(data: aadJSON!, encoding: .utf8)
        
        let ptext = Plaintext(data: plaintext.EncryptableData, aad: Array(messageAAD!.utf8))
        completion(ptext, peacemakrKey, err)
      })
    }
  }
  
  /**
   Returns an encrypted and base64 serialized blob that contains \p plaintext.
   Throws an error on failure of encryption or serialization.
   */
  public func Encrypt(_ plaintext: Encryptable, completion: (@escaping ([UInt8], Error?) -> Void)) -> Void {
    let p = Plaintext(data: plaintext.serializedValue, aad: [UInt8]())
    getEncryptionKey(plaintext: p, completion: { (plaintext, key, err) in
      if err != nil {
        completion([UInt8](), err)
      }
      
      if plaintext == nil {
        self.log("Plaintext was nil")
        completion([UInt8](), NSError(domain: "plaintext was nil", code: -101, userInfo: nil))
        return
      }
      
      if key == nil {
        self.log("key was nil")
        completion([UInt8](), NSError(domain: "key was nil", code: -102, userInfo: nil))
        return
      }
      
      var encrypted = UnwrapCall(self.cryptoContext.Encrypt(
        key: key!,
        plaintext: plaintext!,
        rand: self.rand
      ), onError: self.log)
      if encrypted == nil {
        self.log("Encryption failed")
        completion([UInt8](), NSError(domain: "Encryption failed", code: -103, userInfo: nil))
        return
      }
      
      let signKey = self.getMyKey(priv: true)
      if signKey == nil {
        self.log("Unable to get my private key")
        completion([UInt8](), NSError(domain: "Unable to get my private key", code: -104, userInfo: nil))
        return
      }
      
      self.cryptoContext.Sign(senderKey: signKey!, plaintext: plaintext!, ciphertext: &encrypted!)
      
      let serialized = UnwrapCall(self.cryptoContext.Serialize(encrypted!), onError: self.log)
      if serialized == nil {
        self.log("Serialization failed")
        completion([UInt8](), NSError(domain: "Serialization failed", code: -105, userInfo: nil))
        return
      }
      
      completion(serialized!, nil)
    })
  }
  
  private func getKeyID(serialized: [UInt8]) -> ([UInt8], [UInt8])? {
    let serializedAAD = UnwrapCall(cryptoContext.ExtractUnverifiedAAD(serialized), onError: self.log)
    if serializedAAD == nil {
      return nil
    }
    
    let aadDict = try? JSONSerialization.jsonObject(with: Data(bytes: serializedAAD!.AuthenticatableData), options: [])
    if aadDict == nil {
      self.log("json deserialization of AAD failed")
      return nil
    }
    
    let aad = aadDict as! Dictionary<String, [UInt8]>
    
    return (aad["cryptoKeyID"]!, aad["senderKeyID"]!)
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
        self.log(err!.localizedDescription)
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
