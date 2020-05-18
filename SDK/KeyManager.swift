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
    case loadError

    var localizedDescription: String {
      switch self {
      case .serializationError:
        return "failed to serialize/deserialize"
      case .keygenError:
        return "keygen failed"
      case .saveError:
        return "failed to save"
      case .loadError:
        return "failed to load"
      }
    }
  }

  let defaultSymmetricCipher = SymmetricCipher.CHACHA20_POLY1305

  let testingMode: Bool

  /// MARK: - Initializers

  required public init(testingMode: Bool = false) {
    self.testingMode = testingMode
  }

  
  /// MARK: - Generate New Key Pair

  private func parseIntoCipher(keyType: String, keyLen: Int) -> AsymmetricCipher {
    if keyType == "ec" {
      switch keyLen {
      case 256:
        return .ECDH_P256
      case 384:
        return .ECDH_P384
      case 521:
        return .ECDH_P521
      default:
        return .ECDH_P256
      }
    } else if keyType == "rsa" {
      switch keyLen {
      case 2048:
        return .RSA_2048
      case 4096:
        return .RSA_4096
      default:
        return .RSA_4096
      }
    }

    return .ECDH_P256
  }

  func createKeyPair(with rand: RandomDevice, asymm: AsymmetricCipher) throws -> PeacemakrKey {
    guard let keyPair = PeacemakrKey(asymmCipher: asymm, symmCipher: defaultSymmetricCipher, rand: rand) else {
      throw KeyManagerError.keygenError
    }
    return keyPair
  }

  // Generate and Store keypair
  func createAndStoreKeyPair(with rand: RandomDevice, keyType: String, keyLen: Int) throws -> (priv: Data, pub: Data) {
    let newKeyPair = try createKeyPair(with: rand, asymm: parseIntoCipher(keyType: keyType, keyLen: keyLen))

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

    // Store key creation time in Unix time
    let success = Persister.storeData(Constants.dataPrefix + Constants.keyCreationTime, val: Date().timeIntervalSince1970)
    if !success {
      throw KeyManagerError.saveError
    }

    return (priv, pub)
  }

  func getKeyID(serialized: Data) throws -> (keyID: String, signKeyID: String) {

    guard let serializedAAD = UnwrapCall(CryptoContext.extractUnverifiedAAD(serialized), onError: Logger.onError) else {
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
  func getEncryptionKey(useDomainID: String) -> (aad: String, key: PeacemakrKey, digest: MessageDigestAlgorithm)? {
    
    
    
    guard let keyIDandCfg = self.selectKey(useDomainID: useDomainID) else {
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

    guard let keyToUse = self.getLocalKeyByID(keyID: keyIDandCfg.keyId, cfg: keyIDandCfg.keyConfig) else {
      Logger.error("Unable to get key with ID " + keyIDandCfg.keyId)
      return nil
    }

    return (messageAAD, keyToUse, keyIDandCfg.keyConfig.digestAlgorithm)
  }

  private func parseDigestAlgorithm(digest: String?) -> MessageDigestAlgorithm {
    switch (digest) {
    case Constants.Sha224:
      return .SHA_224
    case Constants.Sha256:
      return .SHA_256
    case Constants.Sha384:
      return .SHA_384
    case Constants.Sha512:
      return .SHA_512
    default:
      return .SHA_256
    }
  }

  private func parseEncryptionAlgorithm(algo: String) -> SymmetricCipher {
    switch (algo) {
    case Constants.Aes128gcm:
      return .AES_128_GCM
    case Constants.Aes192gcm:
      return .AES_192_GCM
    case Constants.Aes256gcm:
      return .AES_256_GCM
    case Constants.Chacha20Poly1305:
      return .CHACHA20_POLY1305
    default:
      return .CHACHA20_POLY1305
    }
  }

  func selectKey(useDomainID: String) -> (keyId: String, keyConfig: CoreCrypto.CryptoConfig)? {
    if self.testingMode {
      return ("my-key-id", CoreCrypto.CryptoConfig(
          mode: CoreCrypto.EncryptionMode.SYMMETRIC,
          symm_cipher: CoreCrypto.SymmetricCipher.CHACHA20_POLY1305,
          asymm_cipher: CoreCrypto.AsymmetricCipher.ASYMMETRIC_UNSPECIFIED,
          digest: CoreCrypto.MessageDigestAlgorithm.SHA_256))
    }

    // Use the string, if it's empty then just use the first one
    guard let encodedUseDomains: Data = Persister.getData(Constants.dataPrefix + Constants.useDomains) else {
      Logger.error("Persisted use domains were nil")
      return nil
    }

    guard let useDomains = try? JSONDecoder().decode([SymmetricKeyUseDomain].self, from: encodedUseDomains) else {
      Logger.error("failed to decode useDomains")
      return nil
    }

    var useDomainToUse = useDomains.randomElement()

    useDomains.forEach { domain in
      if domain._id == useDomainID {
        useDomainToUse = domain
        return
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

    let keyCfg = CoreCrypto.CryptoConfig(mode: .SYMMETRIC,
        symm_cipher: parseEncryptionAlgorithm(algo: domain.symmetricKeyEncryptionAlg),
        asymm_cipher: .ASYMMETRIC_UNSPECIFIED,
        digest: parseDigestAlgorithm(digest: domain.digestAlgorithm))

    return (encryptionKeyID, keyCfg)
  }


  func getMyKey(priv: Bool) -> PeacemakrKey? {
    var tag: String
    if priv {
      tag = Constants.privTag
    } else {
      tag = Constants.pubTag
    }

    // should be base64Encoded? or not?
    guard let keyStr = String(data: Persister.getKey(tag) ?? Data(), encoding: .utf8) else {
      return nil
    }

    return PeacemakrKey(symmCipher: defaultSymmetricCipher, fileContents: keyStr, isPriv: priv)
  }

  func getMyPublicKeyID() -> String {
    guard let pubKeyID: String = Persister.getData(Constants.dataPrefix + Constants.pubKeyIDTag) else {
      return ""
    }

    return pubKeyID
  }


  func getPublicKeyByID(keyID: String, completion: (@escaping (PeacemakrKey?) -> Void)) -> Void {

    if let keyBytes: String = Persister.getData(Constants.dataPrefix + keyID) {

      return completion(PeacemakrKey(symmCipher: defaultSymmetricCipher, fileContents: keyBytes, isPriv: false))

    }

    // QUESTION: else? what will happen if we fail to get keyBytes from persister?

    // we will request it from server?
    let requestBuilder = KeyServiceAPI.getPublicKeyWithRequestBuilder(keyID: keyID)

    requestBuilder.execute({ (key, error) in
      if error != nil {
        Logger.error("failed request public key: " + error!.localizedDescription)
        return completion(nil)
      }
      
      if let keyStr = key?.body?.key {
        if !Persister.storeData(Constants.dataPrefix + keyID, val: keyStr) {
          Logger.error("failed to store key with ID: \(keyID)")
        }
        
        return completion(PeacemakrKey(symmCipher: self.defaultSymmetricCipher, fileContents: keyStr, isPriv: false))
      } else {
        Logger.error("server error")
        return completion(nil)
      }
    })
  }

  func getLocalKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    if keyID == "my-key-id" {
      Logger.error("Using insecure key for local-only testing!")
      return PeacemakrKey(symmCipher: cfg.symmCipher, bytes: Data([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]))
    }

    let tag = Constants.symmTagPrefix + keyID

    guard let keyData = Persister.getKey(tag) else {
      return nil
    }

    return PeacemakrKey(symmCipher: cfg.symmCipher, bytes: keyData)

  }

  func storeKey(key: [UInt8], keyID: [UInt8]) -> Bool {
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

  func rotateClientKeyIfNeeded(rand: RandomDevice, completion: (@escaping (Error?) -> Void)) {
    guard let myPub = getMyKey(priv: false) else {
      Logger.error("unable to get my public key")
      completion(KeyManagerError.loadError)
      return
    }
    let config = myPub.getConfig()

    guard let keyType: String = Persister.getData(Constants.dataPrefix + Constants.clientKeyType),
          let keyLen: Int = Persister.getData(Constants.dataPrefix + Constants.clientKeyLen) else {
      completion(KeyManagerError.loadError)
      return
    }
    let cryptoConfigCipher = parseIntoCipher(keyType: keyType, keyLen: keyLen)

    guard let keyCreationTime: TimeInterval = Persister.getData(Constants.dataPrefix + Constants.keyCreationTime) else {
      completion(KeyManagerError.loadError)
      return
    }

    guard let keyTTL: Int = Persister.getData(Constants.dataPrefix + Constants.clientKeyTTL) else {
      completion(KeyManagerError.loadError)
      return
    }

    // TimeInterval is always in seconds: https://developer.apple.com/documentation/foundation/timeinterval
    let isStale = Int(Date().timeIntervalSince1970 - keyCreationTime) > keyTTL

    if !isStale && cryptoConfigCipher == config.asymmCipher {
      // No error, but bail early cause no rotation needed
      completion(nil)
      return
    }
    Logger.debug("Rotating stale asymmetric keys")

    // Might have to roll back changes
    guard let prevPriv = getMyKey(priv: true) else {
      completion(KeyManagerError.loadError)
      return
    }
    let prevCreationTime = keyCreationTime

    let rollback: (Error) -> Error = { (outerError) in
      // Store private key
      guard let priv = UnwrapCall(prevPriv.toPem(isPriv: true), onError: Logger.onError),
            Persister.storeKey(priv, keyID: Constants.privTag) else {
        Logger.error("In recovering from " + outerError.localizedDescription + " another error ocurred")
        return KeyManagerError.saveError

      }

      // Store public key
      guard let pub = UnwrapCall(prevPriv.toPem(isPriv: false), onError: Logger.onError),
            Persister.storeKey(pub, keyID: Constants.pubTag) else {
        Logger.error("In recovering from " + outerError.localizedDescription + " another error ocurred")
        return KeyManagerError.saveError

      }

      // Store key creation time in Unix time
      let success = Persister.storeData(Constants.dataPrefix + Constants.keyCreationTime, val: prevCreationTime)
      if !success {
        Logger.error("In recovering from " + outerError.localizedDescription + " another error ocurred")
        return KeyManagerError.saveError

      }

      return outerError
    }

    // Do the rotation
    guard let orgID: String = Persister.getData(Constants.dataPrefix + Constants.orgID) else {
      completion(rollback(KeyManagerError.loadError))
      return
    }

    do {
      let keyPair = try createAndStoreKeyPair(with: rand, keyType: keyType, keyLen: keyLen)
      let pubKeyToSend = PublicKey(
          _id: Metadata.shared.pubKeyID,
          creationTime: Int(Date().timeIntervalSince1970),
          keyType: keyType,
          encoding: "pem", 
          key: keyPair.pub.toString(),
          owningClientId: Metadata.shared.clientId,
          owningOrgId: orgID)
      let registerClient = Client(
          _id: Metadata.shared.clientId,
          sdk: Metadata.shared.version,
          preferredPublicKeyId: Metadata.shared.pubKeyID,
          publicKeys: [pubKeyToSend])
      let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)

      requestBuilder.execute({ (resp, error) in
        Logger.info("registration request completed")
        if error != nil {
          Logger.error("addClient failed with " + error.debugDescription)
          completion(rollback(error!))
        }

        guard let response = resp, let body = response.body else {
          Logger.error("server error: response body was nil")
          completion(rollback(NSError(domain: "response body was nil", code: -1, userInfo: nil)))
          return
        }

        // Store the new publicKeyID
        guard Persister.storeData(Constants.dataPrefix + Constants.pubKeyIDTag, val: body.publicKeys.first?._id) else {
          Logger.error("failed to store key pair")
          completion(rollback(NSError(domain: "could not store metadata", code: -2, userInfo: nil)))
          return
        }

        Logger.debug("Rotated client asymmetric keypair")
        completion(nil)
      })
    } catch {
      completion(rollback(error))
    }
  }
}
