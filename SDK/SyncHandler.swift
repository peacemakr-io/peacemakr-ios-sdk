//
//  SynchronizationHandler.swift
//  Peacemakr-iOS
//
//  Created by Yuliia Synytsia on 5/18/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation
import CoreCrypto

class SyncHandler {
  // Stores org ID and crypto config ID
  class func syncOrgInfo(apiKey: String, completion: (@escaping (Error?) -> Void)) -> Void {
    let requestBuilder = OrgAPI.getOrganizationFromAPIKeyWithRequestBuilder(apikey: apiKey)
    requestBuilder.execute { (resp, err) in
      if err != nil {
        Logger.error("Trying to get org from API Key: " + err!.localizedDescription)
        completion(err)
        return
      }
      
      guard let response = resp, let body = response.body else {
        Logger.error("Response body was nil")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }
      
      let orgID = body._id
      let cryptoConfigID = body.cryptoConfigId
      
      if !Persister.storeData(Constants.dataPrefix + "OrgID", val: orgID) {
        completion(NSError(domain: "Unable to store org ID", code: -30, userInfo: nil))
        return
      }
      
      if !Persister.storeData(Constants.dataPrefix + "CryptoConfigID", val: cryptoConfigID) {
        completion(NSError(domain: "Unable to store crypto config ID", code: -31, userInfo: nil))
        return
      }
      
      Logger.debug("got orgID " + orgID + " and cryptoConfigID " + cryptoConfigID)
      
      completion(nil)
    }
  }
  
  class func syncCryptoConfig(completion: (@escaping (Error?) -> Void)) -> Void {
    guard let cryptoConfigID: String = Persister.getData(Constants.dataPrefix + "CryptoConfigID") else {
      completion(NSError(domain: "missing CryptoConfigID", code: -34, userInfo: nil))
      Logger.error("Missing CryptoConfigID")
      return
    }
    
    let requestBuilder = CryptoConfigAPI.getCryptoConfigWithRequestBuilder(cryptoConfigId: cryptoConfigID)
    requestBuilder.execute { (resp, err) in
      if err != nil {
        Logger.error("Trying to get the CryptoConfig: " + err!.localizedDescription)
        completion(err)
        return
      }
      
      guard let response = resp, let body = response.body else {
        Logger.error("Response body was nil")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }
      
      if !Persister.storeData(Constants.dataPrefix + "UseDomainSelectorScheme", val: body.symmetricKeyUseDomainSelectorScheme) {
        Logger.error("Failed to store use domain selector scheme")
        completion(NSError(domain: "failed to store use domain selector scheme", code: -37, userInfo: nil))
      }
      
      guard let data = try? JSONEncoder().encode(body.symmetricKeyUseDomains) else {
        completion(NSError(domain: "Failed to json encode the use domains", code: -36, userInfo: nil))
        return
      }
      
      if !Persister.storeData(Constants.dataPrefix + "UseDomains", val: data) {
        Logger.error("Failed to store use domains")
        completion(NSError(domain: "failed to store use domains", code: -35, userInfo: nil))
      }
      
      Logger.debug("synchronized the crypto config")
      completion(nil)
    }
  }
  
  class func syncSymmetricKeys(completion: (@escaping (Error?) -> Void)) {
    
    guard let myPrivKey = KeyManager.getMyKey(priv: true) else {
      Logger.error("failed to get key")
      completion(NSError(domain: "unable to get key", code: -15, userInfo: nil))
      return
    }
    
    let finishKeyStorage = { (keyPlaintext: Plaintext, keyLen: Int, keyIDs: [String]) -> Void in
      Logger.debug("storing keys: " + keyIDs.joined(separator: ", "))
      
      guard let keyStr = String(bytes: keyPlaintext.encryptableData, encoding: .utf8),
        let keyBytes = Data(base64Encoded: keyStr) else {
          Logger.error("invalid b64 key")
          completion(NSError(domain: "invalid b64 key", code: -15, userInfo: nil))
          return
      }
      
      for (i, keyID) in keyIDs.enumerated() {
        let thisKeyBytes = keyBytes[i*keyLen..<(i+1)*keyLen]
        if !KeyManager.storeKey(key: Array(thisKeyBytes), keyID: Array(keyID.utf8)) {
          Logger.error("failed to store the key with keyID: " + keyID)
          completion(NSError(domain: "Key storage failed", code: -16, userInfo: nil))
          return
        }
      }
      completion(nil)
    }
    
    let requestBuilder = KeyServiceAPI.getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: Metadata.shared.clientId)
    requestBuilder.execute({(keys, error) in
      if error != nil {
        Logger.error("failed to get encrypted keys with " + error!.localizedDescription)
        completion(error)
        return
      }
      
      guard let encKeys = keys, let body = encKeys.body, body.count != 0 else {
        Logger.error("no keys returned in get all encrypted keys request")
        completion(NSError(domain: "No keys were returned", code: -10, userInfo: nil))
        return
      }
      
      
      // Now iterate over the keys in the message
      for key in body {
        // Get the serialized ciphertext
        guard let serialized = key.packagedCiphertext.data(using: .utf8) else { continue }
        
        // Grab the keyID from the ciphertext
        guard let storedKeyIDs = try? KeyManager.getKeyID(serialized: serialized) else {
          Logger.error("Unable to extract key IDs serialized key package")
          completion(NSError(domain: "Unable to extract key IDs", code: -11, userInfo: nil))
          return
        }
        
        guard let deserializedCfg = UnwrapCall(CryptoContext.deserialize(serialized), onError: Logger.onError) else {
          Logger.error("Unable to deserialize key package ciphertext")
          completion(NSError(domain: "Unable to deserialize the key package", code: -12, userInfo: nil))
          return
        }
        var (deserialized, _) = deserializedCfg
        
        // Decrypt the key
        guard let decryptResult = UnwrapCall(CryptoContext.decrypt(recipientKey: myPrivKey, ciphertext: deserialized), onError: Logger.onError) else {
          Logger.error("Unable to decrypt key package ciphertext")
          completion(NSError(domain: "Unable to decrypt the key package", code: -13, userInfo: nil))
          return
        }
        
        let (keyPlaintext, needVerify) = decryptResult
        
        if needVerify {
          KeyManager.getPublicKeyByID(keyID: storedKeyIDs.1, completion: { (pKey) in
            if pKey == nil {
              Logger.error("Public key: " + storedKeyIDs.signKeyID + " could not be gotten")
              completion(NSError(domain: "Could not get signer public key", code: -14, userInfo: nil))
              return
            }
            Utilities.verifyMessage(plaintext: keyPlaintext, ciphertext: &deserialized, verifyKey: pKey!, completion: {(verified) in
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

}
