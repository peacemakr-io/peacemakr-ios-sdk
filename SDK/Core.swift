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


  private var version: String {

    if let bundleInfo = Bundle(for: type(of: self)).infoDictionary,
      let shortVersion = bundleInfo["CFBundleShortVersionString"] as? String,
      let bundleVersion = bundleInfo["CFBundleVersion"] as? String {

      return "\(shortVersion).\(bundleVersion)"
    } else {
      return "<Unknown Peacemakr SDK version>"
    }
  }

  private let cryptoContext: CryptoContext
  private var rand: RandomDevice
  private let apiKey: String
  private var logHandler: (String) -> Void
  private let myKeyCfg = CoreCrypto.CryptoConfig(
    mode: EncryptionMode.ASYMMETRIC,
    symm_cipher: SymmetricCipher.AES_256_GCM,
    asymm_cipher: AsymmetricCipher.RSA_4096,
    digest: MessageDigestAlgorithm.SHA_512
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

    guard let cryptoCtxt = CryptoContext() else {
      return nil
    }

    self.apiKey = apiKey
    self.logHandler = logHandler

    self.cryptoContext = cryptoCtxt
    self.rand = PeacemakrRandomDevice()

    self.persister = DefaultPersister(logHandler: self.logHandler)

    // TODO: move to configuration file
//    SwaggerClientAPI.basePath = SwaggerClientAPI.basePath.replacingOccurrences(of: "http", with: "https")
    SwaggerClientAPI.basePath = "http://localhost:8080/api/v1"
    SwaggerClientAPI.customHeaders = ["Authorization": self.apiKey]
  }

  private func log(_ s: String) -> Void {
    let logStr = s + " - SDK Version: iOS-" + self.version
    
    if self.registrationSuccessful {
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

  public var registrationSuccessful: Bool {
    get {
      return self.persister.hasData(self.dataPrefix + self.clientIDTag) && self.persister.hasData(self.dataPrefix + self.pubKeyIDTag)
    }
  }

  public func register(completion: (@escaping (Error?) -> Void)) {

    // Generate my keypair
    guard let myKey = PeacemakrKey(asymmCipher: myKeyCfg.asymmCipher, symmCipher: myKeyCfg.symmCipher, rand: rand) else {
      self.log("Keygen failed")
      // TODO: Create Peacemakr Error enum
      // Better error handling in Swift 4.2
      completion(NSError(domain:"Keygen failed", code: -2, userInfo:nil))
      return
    }

    // Store private key
    guard let priv = UnwrapCall(myKey.toPem(isPriv: true), onError: self.log),
      self.persister.storeKey(priv, keyID: self.privTag) else {
      self.log("Storing my private key failed")
      completion(NSError(domain:"Storing my private key failed", code: -2, userInfo:nil))
      return
    }

    // Store public key
    guard let pub = UnwrapCall(myKey.toPem(isPriv: false), onError: self.log),
      self.persister.storeKey(pub, keyID: self.pubTag) else {
      self.log("Storing my public key failed")
      return
    }

    // Call up to server and register myself
    let pubKeyToSend = PublicKey(_id: "", creationTime: Int(Date().timeIntervalSince1970), keyType: "rsa", encoding: "pem", key: pub.toString())

    let registerClient = Client(_id: "", sdk: version, publicKey: pubKeyToSend)

    let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)

    requestBuilder.execute({ (resp, error) in
      self.logHandler("Register request completed")
      if error != nil {
        self.log("addClient failed with " + error.debugDescription)
        completion(error)
        return
      }

      guard let response = resp, let body = response.body else {
        self.log("Response body was nil")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }

    // Store the clientID and publicKeyID
     guard self.persister.storeData(self.dataPrefix + self.clientIDTag, val: body._id),
          self.persister.storeData(self.dataPrefix + self.pubKeyIDTag, val: body.publicKey._id) else {
        self.log("couldn't store client ID or  public key ID")
        completion(NSError(domain: "could not store metadata", code: -2, userInfo: nil))
        return
      }

      self.log("Registered new iOS client: " + self.getMyClientID())
      completion(nil)
    })
  }

  private func getMyClientID() -> String {
    guard let clientId: String = self.persister.getData(self.dataPrefix + self.clientIDTag) else {
      self.logHandler("failed to get my client ID")
      return ""
    }

    return clientId
  }

  public func sync(completion: (@escaping (Error?) -> Void)) -> Void {
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

      return completion(PeacemakrKey(asymmCipher: cfg.asymmCipher, symmCipher: cfg.symmCipher, fileContents: keyBytes, isPriv: false))

    }

    // QUESTION: else? what will happen if we fail to get keyBytes from persister?

    // we will request it from server?
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

        return completion(PeacemakrKey(asymmCipher: cfg.asymmCipher, symmCipher: cfg.symmCipher, fileContents: keyStr, isPriv: false))
      }

      self.log("Attempted to get public key, and the response was empty")
      return completion(nil)
    })
  }

  private func getLocalKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let tag = symmTagPrefix + keyID

    guard let keyData = self.persister.getKey(tag) else {
      self.log("Could not retreive key at: " + tag)
      return nil
    }

    return PeacemakrKey(symmCipher: cfg.symmCipher, bytes: keyData)

  }

  private func verifyMessage(plaintext: Plaintext, ciphertext: inout Ciphertext, verifyKey: PeacemakrKey, completion: (@escaping (Bool) -> Void)) {
    let verified = UnwrapCall(self.cryptoContext.verify(senderKey: verifyKey, plaintext: plaintext, ciphertext: &ciphertext), onError: self.log)
    if verified == nil || verified == false {
      completion(false)
    }
    completion(true)
  }

  private func syncSymmetricKeys(completion: (@escaping (Error?) -> Void)) {
    let myClientID = getMyClientID()

    guard let myPrivKey = getMyKey(priv: true) else {
      completion(NSError(domain: "unable to get key", code: -15, userInfo: nil))
      return
    }

    let finishKeyStorage = { (keyPlaintext: Plaintext, keyLen: Int, keyIDs: [String]) -> Void in
      self.log("Storing keys: " + keyIDs.joined(separator: ", "))

      guard let keyStr = String(bytes: keyPlaintext.encryptableData, encoding: .utf8),
            let keyBytes = Data(base64Encoded: keyStr) else {
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

      guard let encKeys = keys, let body = encKeys.body, body.count != 0 else {
        self.log("no keys returned in get all encrypted keys request")
        completion(NSError(domain: "No keys were returned", code: -10, userInfo: nil))
        return
      }


      // Now iterate over the keys in the message
      for key in body {
        // Get the serialized ciphertext
        guard let serialized = key.packagedCiphertext.data(using: .utf8) else { continue }

        // Grab the keyID from the ciphertext
        guard let storedKeyIDs = self.getKeyID(serialized: serialized) else {
          self.log("Unable to extract key IDs serialized key package")
          completion(NSError(domain: "Unable to extract key IDs", code: -11, userInfo: nil))
          return
        }

        guard let deserializedCfg = UnwrapCall(self.cryptoContext.deserialize(serialized), onError: self.log) else {
          self.log("Unable to deserialize key package ciphertext")
          completion(NSError(domain: "Unable to deserialize the key package", code: -12, userInfo: nil))
          return
        }
        var (deserialized, _) = deserializedCfg

        // Decrypt the key
        guard let decryptResult = UnwrapCall(self.cryptoContext.decrypt(key: myPrivKey, ciphertext: deserialized), onError: self.log) else {
          self.log("Unable to decrypt key package ciphertext")
          completion(NSError(domain: "Unable to decrypt the key package", code: -13, userInfo: nil))
          return
        }

        let (keyPlaintext, needVerify) = decryptResult

        if needVerify {
          self.getPublicKeyByID(keyID: storedKeyIDs.1, cfg: self.myKeyCfg, completion: { (pKey) in
            if pKey == nil {
              self.log("Public key: " + storedKeyIDs.signKeyID + " could not be gotten")
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

    // should be base64Encoded? or not?
    guard let keyData = self.persister.getKey(tag) else {
      self.log("unable to get my key (public/private) from keychain")
      return nil
    }

    return PeacemakrKey(asymmCipher: myKeyCfg.asymmCipher,
                        symmCipher: myKeyCfg.symmCipher,
                        fileContents: keyData.base64EncodedString(),
                        isPriv: priv)
  }

  private func getMyPublicKeyID() -> String {
    guard let pubKeyID: String = self.persister.getData(self.dataPrefix + self.pubKeyIDTag) else {
      self.log("failed to get my public key ID from the filesystem")
      return ""
    }

    return pubKeyID
  }

  // Stores org ID and crypto config ID
  private func syncOrgInfo(completion: (@escaping (Error?) -> Void)) -> Void {
    let requestBuilder = OrgAPI.getOrganizationFromAPIKeyWithRequestBuilder(apikey: self.apiKey)
    requestBuilder.execute { (resp, err) in
      if err != nil {
        self.log("Trying to get org from API Key: " + err!.localizedDescription)
        completion(err)
        return
      }

      guard let response = resp, let body = response.body else {
        self.log("Response body was nil")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }

      let orgID = body._id
      let cryptoConfigID = body.cryptoConfigId

      if !self.persister.storeData(self.dataPrefix + "OrgID", val: orgID) {
        self.log("Unable to store OrgID")
        completion(NSError(domain: "Unable to store org ID", code: -30, userInfo: nil))
        return
      }

      if !self.persister.storeData(self.dataPrefix + "CryptoConfigID", val: cryptoConfigID) {
        self.log("Unable to store CryptoConfigID")
        completion(NSError(domain: "Unable to store crypto config ID", code: -31, userInfo: nil))
        return
      }

      self.log("got orgID " + orgID + " and cryptoConfigID " + cryptoConfigID)

      completion(nil)
    }
  }

  private func syncCryptoConfig(completion: (@escaping (Error?) -> Void)) -> Void {
    guard let cryptoConfigID: String = self.persister.getData(self.dataPrefix + "CryptoConfigID") else {
      completion(NSError(domain: "missing CryptoConfigID", code: -34, userInfo: nil))
      self.log("Missing CryptoConfigID")
      return
    }

    let requestBuilder = CryptoConfigAPI.getCryptoConfigWithRequestBuilder(cryptoConfigId: cryptoConfigID)
    requestBuilder.execute { (resp, err) in
      if err != nil {
        self.log("Trying to get the CryptoConfig: " + err!.localizedDescription)
        completion(err)
        return
      }

      guard let response = resp, let body = response.body else {
        self.log("Response body was nil")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }

      if !self.persister.storeData(self.dataPrefix + "UseDomainSelectorScheme", val: body.symmetricKeyUseDomainSelectorScheme) {
        self.log("Failed to store use domain selector scheme")
        completion(NSError(domain: "failed to store use domain selector scheme", code: -37, userInfo: nil))
      }

      guard let data = try? JSONEncoder().encode(body.symmetricKeyUseDomains) else {
        completion(NSError(domain: "Failed to json encode the use domains", code: -36, userInfo: nil))
        return
      }

      if !self.persister.storeData(self.dataPrefix + "UseDomains", val: data) {
        self.log("Failed to store use domains")
        completion(NSError(domain: "failed to store use domains", code: -35, userInfo: nil))
      }

      self.log("Synchronized the crypto config")
      completion(nil)
    }
  }

  private func selectKey(useDomainID: String) -> (keyId: String, keyConfig: CoreCrypto.CryptoConfig)? {
    // Use the string, if it's empty then just use the first one
    guard let encodedUseDomains: Data = self.persister.getData(self.dataPrefix + "UseDomains") else {
      self.log("Persisted use domains were nil")
      return nil
    }

//    let useDomainSelector: String? = self.persister.getData(self.dataPrefix + "UseDomainSelectorScheme")
//    if useDomainSelector == nil {
//      self.log("Persisted use domain selector scheme was nil")
//      return nil
//    }

    guard let useDomains = try? JSONDecoder().decode([SymmetricKeyUseDomain].self, from: encodedUseDomains) else {
      self.log("Unable to encode useDomains")
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
      self.log("Invalid use domain, no key IDs contained within")
      return nil
    }

    guard let encryptionKeyID = domain.encryptionKeyIds.randomElement() else {
      self.log("Invalid encryption key ID")
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

  // This edits the plaintext to add the key ID to the message before it gets encrypted and sent out
  private func getEncryptionKey(useDomainID: String) -> (aad: String, key: PeacemakrKey)? {

    guard let keyIDandCfg = self.selectKey(useDomainID: useDomainID) else {
      self.log("Unable to select a key")
      return nil
    }

    let myPubKeyID = self.getMyPublicKeyID()

    let jsonObject: [String: String] = ["cryptoKeyID": keyIDandCfg.keyId, "senderKeyID": myPubKeyID]

    guard let aadJSON = try? JSONSerialization.data(withJSONObject: jsonObject, options: []),
      let messageAAD = String(data: aadJSON, encoding: .utf8) else {
      self.log("Failed to serialize the key IDs to json")
      return nil
    }

    guard let keyToUse = self.getLocalKeyByID(keyID: keyIDandCfg.keyId, cfg: keyIDandCfg.keyConfig) else {
      self.log("Unable to get key with ID " + keyIDandCfg.keyId)
      return nil
    }

    return (messageAAD, keyToUse)
  }

  /**
   Returns an encrypted and base64 serialized blob that contains \p plaintext.
   Throws an error on failure of encryption or serialization.
   */
  public func encrypt(_ plaintext: Encryptable, useDomainID: String? = nil) -> (Data?, Error?) {
    guard let aadAndKey = self.getEncryptionKey(useDomainID: useDomainID ?? ""),
    let aadData = aadAndKey.aad.data(using: .utf8) else {
      return (nil, NSError(domain: "Unable to get the encryption key", code: -101, userInfo: nil))
    }
    let p = Plaintext(data: plaintext.serializedValue, aad: aadData)

    guard let encrypted = UnwrapCall(self.cryptoContext.encrypt(
      key: aadAndKey.key,
      plaintext: p,
      rand: self.rand
    ), onError: self.log) else {
      self.log("Encryption failed")
      return (nil, NSError(domain: "Encryption failed", code: -103, userInfo: nil))
    }

    var encCiphertext = encrypted

    guard let signKey = self.getMyKey(priv: true) else {
      self.log("Unable to get my private key")
      return (nil, NSError(domain: "Unable to get my private key", code: -104, userInfo: nil))
    }

    // NOTE: I set .DIGEST_UNSPECIFIED because I am not sure what it should be
    self.cryptoContext.sign(senderKey: signKey, plaintext: p, digest: .DIGEST_UNSPECIFIED, ciphertext: &encCiphertext)

    guard let serialized = UnwrapCall(self.cryptoContext.serialize(.DIGEST_UNSPECIFIED, encCiphertext), onError: self.log) else {
      self.log("Serialization failed")
      return (nil, NSError(domain: "Serialization failed", code: -105, userInfo: nil))
    }

    return (serialized, nil)
  }

  private func getKeyID(serialized: Data) -> (keyID: String, signKeyID: String)? {

    guard let serializedAAD = UnwrapCall(cryptoContext.extractUnverifiedAAD(serialized), onError: self.log),
      let aadDict = try? JSONSerialization.jsonObject(with: serializedAAD.authenticatableData, options: []) else {
      self.log("json deserialization of AAD failed")
      return nil
    }

    guard let aad = aadDict as? [String: Any],
      let senderKeyID = aad["senderKeyID"] as? String,
      let cryptoKeyID = aad["cryptoKeyID"] as? String else {
      return ("", "")
    }

    return (cryptoKeyID, senderKeyID)

  }

  /**
   Deserializes and decrypts \p serialized and stores the output into \p dest.
   Throws an error on failure of deserialization or decryption.
   */
  public func decrypt(_ serialized: Data, dest: Encryptable, completion: (@escaping (Encryptable) -> Void)) -> Bool {

    guard let keyIDs = getKeyID(serialized: serialized) else {
      self.log("Unable to parse key IDs from message")
      return false
    }

    guard let deserializedCfg = UnwrapCall(cryptoContext.deserialize(serialized), onError: self.log) else {
      self.log("Unable to deserialize encrypted message")
      return false
    }
    var (deserialized, cfg) = deserializedCfg

    // Get the key specified by the message
    getSymmKeyByID(keyID: keyIDs.keyID, cfg: cfg, completion: { (key, err) in
      var dest = dest
      if err != nil {
        self.log("Trying to get the symmetric key: " + err!.localizedDescription)
        dest.onError(error: err!)
        completion(dest)
        return
      }
      guard let symmKey = key else {
        self.log("Unable to get symmetric key for decrypting the messaage")
        dest.onError(error: NSError(domain: "Unable to get symmetric decrypt key", code: -106, userInfo: nil))
        completion(dest)
        return
      }

      // Then decrypt
      guard let decryptResult = UnwrapCall(self.cryptoContext.decrypt(key: symmKey, ciphertext: deserialized), onError: self.log) else {
        self.log("Decryption failed")
        dest.onError(error: NSError(domain: "Decryption failed", code: -107, userInfo: nil))
        completion(dest)
        return
      }

      let (outPlaintext, needsVerify) = decryptResult
      // And verify (which is another callback)
      if needsVerify {
        self.getPublicKeyByID(keyID: keyIDs.signKeyID, cfg: self.myKeyCfg, completion: { (verifyKey) in
          self.verifyMessage(plaintext: outPlaintext, ciphertext: &deserialized, verifyKey: verifyKey!, completion: { (verified) in
            if !verified {
              self.log("Verification failed")
              dest.onError(error: NSError(domain: "Verification failed", code: -108, userInfo: nil))
              completion(dest)
              return
            }
            dest.serializedValue = outPlaintext.encryptableData
            completion(dest)
          })
        })
      } else {
        dest.serializedValue = outPlaintext.encryptableData
        completion(dest)
      }
    })

    return true
  }

}
