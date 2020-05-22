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
  
  let keyManager: KeyManager
  let persister: Persister
  /// MARK: - Initializers

  required public init(persister: Persister, keyManager: KeyManager) {
    self.persister = persister
    self.keyManager = keyManager
  }
  
  // Stores org ID and crypto config ID
  func syncOrgInfo(apiKey: String, completion: (@escaping (Error?) -> Void)) -> Void {
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

      if !self.persister.storeData(Constants.dataPrefix + "OrgID", val: orgID) {
        completion(NSError(domain: "Unable to store org ID", code: -30, userInfo: nil))
        return
      }

      if !self.persister.storeData(Constants.dataPrefix + "CryptoConfigID", val: cryptoConfigID) {
        completion(NSError(domain: "Unable to store crypto config ID", code: -31, userInfo: nil))
        return
      }

      Logger.debug("got orgID " + orgID + " and cryptoConfigID " + cryptoConfigID)

      completion(nil)
    }
  }

  func syncCryptoConfig(completion: (@escaping (Error?) -> Void)) -> Void {
    guard let cryptoConfigID: String = self.persister.getData(Constants.dataPrefix + Constants.cryptoConfigID) else {
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

      if !self.persister.storeData(Constants.dataPrefix + Constants.udSelectorScheme, val: body.symmetricKeyUseDomainSelectorScheme) {
        Logger.error("Failed to store use domain selector scheme")
        completion(NSError(domain: "failed to store use domain selector scheme", code: -37, userInfo: nil))
      }

      guard let data = try? JSONEncoder().encode(body.symmetricKeyUseDomains) else {
        completion(NSError(domain: "Failed to json encode the use domains", code: -36, userInfo: nil))
        return
      }

      if !self.persister.storeData(Constants.dataPrefix + Constants.useDomains, val: data) {
        Logger.error("Failed to store use domains")
        completion(NSError(domain: "failed to store use domains", code: -35, userInfo: nil))
      }

      // If you're looking for when the client is going to re-regesiter a new key
      // due to a server side config change, go checkout rotateClientKeyIfNeeded.
      if !self.persister.storeData(Constants.dataPrefix + Constants.clientKeyType, val: body.clientKeyType) {
        Logger.error("Failed to store client key type")
        completion(NSError(domain: "failed to store client key type", code: -38, userInfo: nil))
      }

      if !self.persister.storeData(Constants.dataPrefix + Constants.clientKeyLen, val: body.clientKeyBitlength) {
        Logger.error("Failed to store client key length")
        completion(NSError(domain: "failed to store client key length", code: -39, userInfo: nil))
      }

      if !self.persister.storeData(Constants.dataPrefix + Constants.clientKeyTTL, val: body.clientKeyTTL) {
        Logger.error("Failed to store client key TTL")
        completion(NSError(domain: "failed to store client key TTL", code: -40, userInfo: nil))
      }

      Logger.debug("synchronized the crypto config")
      completion(nil)
    }
  }

  func syncSymmetricKeys(keyIDs: [String]?, completion: (@escaping (Error?) -> Void)) {

    guard let myPrivKey = self.keyManager.getMyKey(priv: true) else {
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
        let thisKeyBytes = keyBytes[i * keyLen..<(i + 1) * keyLen]
        if !self.keyManager.storeKey(key: Array(thisKeyBytes), keyID: Array(keyID.utf8)) {
          Logger.error("failed to store the key with keyID: " + keyID)
          completion(NSError(domain: "Key storage failed", code: -16, userInfo: nil))
          return
        }
      }
      completion(nil)
    }

    let requestBuilder = KeyServiceAPI.getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: Metadata.shared.getPubKeyID(persister: self.persister), symmetricKeyIds: keyIDs)
    requestBuilder.execute({ (keys, error) in
      if error != nil {
        Logger.error("failed to get encrypted keys with " + error!.localizedDescription)
        completion(error)
        return
      }

      guard let encKeys = keys, let body = encKeys.body, body.count != 0 else {
        Logger.info("no keys returned in get all encrypted keys request")
        // Per testing seen with Daniel, sometimes Sync returns nothing.
        // And that's ok.
        // completion(NSError(domain: "No keys were returned", code: -10, userInfo: nil))
        completion(nil)
        return
      }

      // Now iterate over the keys in the message
      for key in body {
        // Get the serialized ciphertext
        guard let serialized = key.packagedCiphertext.data(using: .utf8) else {
          Logger.debug("Unable to get utf8 data from key") 
          continue
        }

        // Grab the keyID from the ciphertext
        guard let storedKeyIDs = try? self.keyManager.getKeyID(serialized: serialized) else {
          Logger.error("Unable to extract key IDs serialized key package")
          completion(NSError(domain: "Unable to extract key IDs", code: -11, userInfo: nil))
          return
        }

        // Get the verification key
        self.keyManager.getPublicKeyByID(keyID: storedKeyIDs.1, completion: { (pKey) in
          if pKey == nil {
            Logger.error("Public key: " + storedKeyIDs.signKeyID + " could not be gotten")
            completion(NSError(domain: "Could not get signer public key", code: -14, userInfo: nil))
            return
          }

          guard let deserializedCfg = UnwrapCall(CryptoContext.deserialize(serialized), onError: Logger.onError) else {
            Logger.error("Unable to deserialize key package ciphertext")
            completion(NSError(domain: "Unable to deserialize the key package", code: -12, userInfo: nil))
            return
          }
          var (deserialized, _) = deserializedCfg

          // If ECDH then do the keygen
          var decryptKey: PeacemakrKey
          if myPrivKey.getConfig().asymmCipher.rawValue >= AsymmetricCipher.ECDH_P256.rawValue {
            guard let ecdhKey = PeacemakrKey(symmCipher: deserializedCfg.1.symmCipher, myKey: myPrivKey, peerKey: pKey!) else {
              Logger.error("Unable to perform ECDH Keygen")
              completion(NSError(domain: "Unable to perform ECDH Keygen", code: -12, userInfo: nil))
              return
            }
            decryptKey = ecdhKey
          } else {
            decryptKey = myPrivKey
          }

          // Decrypt the key
          guard let decryptResult = UnwrapCall(CryptoContext.decrypt(key: decryptKey, ciphertext: deserialized), onError: Logger.onError) else {
            Logger.error("Unable to decrypt key package ciphertext")
            completion(NSError(domain: "Unable to decrypt the key package", code: -13, userInfo: nil))
            return
          }

          let (keyPlaintext, needVerify) = decryptResult

          if needVerify {
            if Utilities.verifyMessage(plaintext: keyPlaintext, ciphertext: &deserialized, verifyKey: pKey!) {
              finishKeyStorage(keyPlaintext, key.keyLength, key.keyIds)
            } else {
              completion(NSError(domain: "Unable to verify message", code: -20, userInfo: nil))
            }
          } else {
            finishKeyStorage(keyPlaintext, key.keyLength, key.keyIds)
          }
        })
      }
    })
  }
}
