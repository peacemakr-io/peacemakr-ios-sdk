//
//  KeyManager.swift
//  Peacemakr-iOS
//
//  Created by Yuliia Synytsia on 5/18/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation
import CoreCrypto



class KeyManager {
  
  enum KeyManagerError: Error {
    case serializationError
    case keygenError
    case saveError
    
    var localizedDescription: String {
      switch self {
      case .serializationError:
        return "failed to serialize/deserialize"
      case .keygenError:
        return "keygen failed"
      case .saveError:
        return "failed to save"
        
      }
    }
  }
  
  /// MARK: - Core Crypto Configuration
  
  static let myKeyCfg = CoreCrypto.CryptoConfig(
    mode: EncryptionMode.ASYMMETRIC,
    symm_cipher: SymmetricCipher.AES_256_GCM,
    asymm_cipher: AsymmetricCipher.RSA_4096,
    digest: MessageDigestAlgorithm.SHA_512
  )
  
  /// MARK: - Generate New Key Pair
  class func  createKeyPair(with rand: RandomDevice) throws -> PeacemakrKey {
    guard let keyPair = PeacemakrKey(asymmCipher: myKeyCfg.asymmCipher, symmCipher: myKeyCfg.symmCipher, rand: rand) else {
      throw KeyManagerError.keygenError
    }
    return keyPair

  }
  // Generate and Store keypair
  class func  createAndStoreKeyPair(with rand: RandomDevice) throws -> (priv: Data, pub: Data) {
    
    let newKeyPair = try createKeyPair(with: rand)
    
    // Store private key
    guard let priv = UnwrapCall(newKeyPair.toPem(isPriv: true), onError: Logger.onError),
      Persister.storeKey(priv, keyID: Constants.privTag) else {
        throw KeyManagerError.saveError
    }
    
    // Store public key
    guard let pub = UnwrapCall(newKeyPair.toPem(isPriv: false), onError: Logger.onError),
      Persister.storeKey(pub, keyID: Constants.pubTag) else {
         throw KeyManagerError.saveError
    }
    
    return (priv, pub)
  }
  
  class func getKeyID(serialized: Data, cryptoContext: CryptoContext) throws -> (keyID: String, signKeyID: String) {
    
    guard let serializedAAD = UnwrapCall(cryptoContext.extractUnverifiedAAD(serialized), onError: Logger.onError)  else {
      throw KeyManagerError.serializationError
    }
    
    let aadDict = try JSONSerialization.jsonObject(with: serializedAAD.authenticatableData, options: [])
    
    guard let aad = aadDict as? [String: Any],
      let senderKeyID = aad["senderKeyID"] as? String,
      let cryptoKeyID = aad["cryptoKeyID"] as? String else {
       throw KeyManagerError.serializationError
    }
    
    return (cryptoKeyID, senderKeyID)
    
  }
  
  // This edits the plaintext to add the key ID to the message before it gets encrypted and sent out
  class func getEncryptionKey(useDomainID: String) -> (aad: String, key: PeacemakrKey)? {
    
    guard let keyIDandCfg = KeyManager.selectKey(useDomainID: useDomainID) else {
      Logger.error("failed to select a key")
      return nil
    }
    
    let myPubKeyID = self.getMyPublicKeyID()
    
    let jsonObject: [String: String] = ["cryptoKeyID": keyIDandCfg.keyId, "senderKeyID": myPubKeyID]
    
    guard let aadJSON = try? JSONSerialization.data(withJSONObject: jsonObject, options: []),
      let messageAAD = String(data: aadJSON, encoding: .utf8) else {
        Logger.error("failed to serialize the key IDs to json")
        return nil
    }
    
    guard let keyToUse = KeyManager.getLocalKeyByID(keyID: keyIDandCfg.keyId, cfg: keyIDandCfg.keyConfig) else {
      Logger.error("Unable to get key with ID " + keyIDandCfg.keyId)
      return nil
    }
    
    return (messageAAD, keyToUse)
  }
  
  class func selectKey(useDomainID: String) -> (keyId: String, keyConfig: CoreCrypto.CryptoConfig)? {
    // Use the string, if it's empty then just use the first one
    guard let encodedUseDomains: Data = Persister.getData(Constants.dataPrefix + "UseDomains") else {
      Logger.error("Persisted use domains were nil")
      return nil
    }
    
    guard let useDomains = try? JSONDecoder().decode([SymmetricKeyUseDomain].self, from: encodedUseDomains) else {
      Logger.error("failed to encode useDomains")
      return nil
    }
    
    // TODO: SymmetricKeyUseDomain() should initialize with all set to nil
    // var useDomainToUse = SymmetricKeyUseDomain()
    var useDomainToUse = useDomains.randomElement()
    
    useDomains.forEach { domain in
      if domain._id == useDomainID {
        useDomainToUse = domain
      }
    }
    
    guard let domain = useDomainToUse else {
      Logger.error("invalid use domain, no key IDs contained within")
      return nil
    }
    
    guard let encryptionKeyID = domain.encryptionKeyIds.randomElement() else {
      Logger.error("Invalid encryption key ID")
      return nil
    }
    
    var keyCfg = CoreCrypto.CryptoConfig(mode: .SYMMETRIC,
                                         symm_cipher: .CHACHA20_POLY1305,
                                         asymm_cipher: .ASYMMETRIC_UNSPECIFIED,
                                         digest: .SHA_512)
    
    if domain.symmetricKeyEncryptionAlg == "AESGCM" {
      
      keyCfg = CoreCrypto.CryptoConfig(mode: .SYMMETRIC,
                                       symm_cipher: .AES_256_GCM,
                                       asymm_cipher: .ASYMMETRIC_UNSPECIFIED,
                                       digest: .SHA_512)
    }
    
    
    return (encryptionKeyID, keyCfg)
  }
  
  
  class func getMyKey(priv: Bool) -> PeacemakrKey? {
    var tag: String
    if priv {
      tag = Constants.privTag
    } else {
      tag = Constants.pubTag
    }
    
    // should be base64Encoded? or not?
    guard let keyData = Persister.getKey(tag) else {
      return nil
    }
    
    return PeacemakrKey(asymmCipher: KeyManager.myKeyCfg.asymmCipher,
                        symmCipher: myKeyCfg.symmCipher,
                        fileContents: keyData.base64EncodedString(),
                        isPriv: priv)
  }
  
  class func getMyPublicKeyID() -> String {
    guard let pubKeyID: String = Persister.getData(Constants.dataPrefix + Constants.pubKeyIDTag) else {
      return ""
    }
    
    return pubKeyID
  }
  
  
  class func getPublicKeyByID(keyID: String, completion: (@escaping (PeacemakrKey?) -> Void)) -> Void {
    
    if let keyBytes: String = Persister.getData(Constants.dataPrefix + keyID) {
      
      return completion(PeacemakrKey(asymmCipher: myKeyCfg.asymmCipher, symmCipher: myKeyCfg.symmCipher, fileContents: keyBytes, isPriv: false))
      
    }
    
    // QUESTION: else? what will happen if we fail to get keyBytes from persister?
    
    // we will request it from server?
    let requestBuilder = KeyServiceAPI.getPublicKeyWithRequestBuilder(keyID: keyID)
    
    requestBuilder.execute({(key, error) in
      if error != nil {
        Logger.error("failed request public key: " + error!.localizedDescription)
        return completion(nil)
      }
      
      if let keyStr = key?.body?.key {
        if !Persister.storeData(Constants.dataPrefix + keyID, val: keyStr) {
          Logger.error("failed to store key with ID: \(keyID)")
        }
        
        return completion(PeacemakrKey(asymmCipher: myKeyCfg.asymmCipher, symmCipher: myKeyCfg.symmCipher, fileContents: keyStr, isPriv: false))
      } else {
        Logger.error("server error")
        return completion(nil)
      }
    })
  }
  
  class func getLocalKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let tag = Constants.symmTagPrefix + keyID
    
    guard let keyData = Persister.getKey(tag) else {
      return nil
    }
    
    return PeacemakrKey(symmCipher: cfg.symmCipher, bytes: keyData)
    
  }
  
  class func storeKey(key: [UInt8], keyID: [UInt8]) -> Bool {
    guard let keyIDStr = String(bytes: keyID, encoding: .utf8) else {
      Logger.error("failed to serialize keyID to string")
      return false
    }
    let tag = Constants.symmTagPrefix + keyIDStr
    
    var keyData: Data? = nil
    key.withUnsafeBufferPointer { buf -> Void in
      keyData = Data(buffer: buf)
    }
    
    return Persister.storeKey(keyData!, keyID: tag)
  }
}
