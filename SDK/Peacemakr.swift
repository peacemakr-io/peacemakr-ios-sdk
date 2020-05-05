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
public class Peacemakr: PeacemakrProtocol {

  /// MARK: - Peacemakr Errors

  enum PeacemakrError: Error {
    case initializationError
    case registrationError
    case keyManagerError
    case keyConfigurationError
    case keyCreationError
    case keyFetchError
    case blobUnwrapError
    case encryptionError
    case signingError
    case serializationError
    case deserializationError
    case decryptionError
    case verificationError
    case apiKeyRequiredInProduction
    case apiKeyProhibitedInStaging


    var localizedDescription: String {
      switch self {
      case .initializationError:
        return "failed to initialize core-crypto libraries"
      case .registrationError:
        return "failed to register to Peacemakr"
      case .keyManagerError:
        return "failed to access keys"
      case .keyConfigurationError:
        return "failed to retrieve configuration for client keypair"
      case .keyCreationError:
        return "failed to generate client asymmetric keys"
      case .keyFetchError:
        return "failed to fetch the symmetric key"
      case .blobUnwrapError:
        return "failed to unwrap blob to get metadata"
      case .encryptionError:
        return "encryption failed"
      case .signingError:
        return "signing failed"
      case .serializationError:
        return "serialization failed"
      case .deserializationError:
        return "deserialization failed"
      case .decryptionError:
        return "decryption failed"
      case .verificationError:
        return "verification failed"
      case .apiKeyRequiredInProduction:
        return "an apikey is required in production mode"
      case .apiKeyProhibitedInStaging:
      return "an apikey may not be used in testing mode"
      }
    }
  }

  /// Peacemakr iOS SDK version number
  public var version: String {
    return Metadata.shared.version
  }

  /// MARK: - CoreCrypto

  private var rand: RandomDevice

  /// MARK: - Properties

  private let apiKey: String
  
  private let url: String
  
  private let testingMode: Bool
  
  private let keyManager: KeyManager
  private let syncHandler: SyncHandler
  private let persister: Persister

  /// MARK: - Initializers

  required public init(apiKey: String, url: String, testingMode: Bool = false) throws {

    if !CryptoContext.setup() {
      throw PeacemakrError.initializationError
    }

    self.apiKey = apiKey
    if apiKey.isEmpty && testingMode == false {
      throw PeacemakrError.apiKeyRequiredInProduction
    }
    
    if !apiKey.isEmpty && testingMode == true {
      throw PeacemakrError.apiKeyProhibitedInStaging
    }
    
    self.testingMode = testingMode
    self.persister = Persister()
    self.keyManager = KeyManager(persister: persister, testingMode: testingMode)
    self.syncHandler = SyncHandler(persister: persister, keyManager: self.keyManager)

    self.rand = PeacemakrRandomDevice()
    
    if url.isEmpty {
      // The default URL should point to prod.
      self.url = "https://api.peacemakr.io"
    } else {
      self.url = url
    }

    SwaggerClientAPI.basePath = url + "/api/v1"
    SwaggerClientAPI.customHeaders = ["Authorization": self.apiKey]
  }

  /// MARK: - Registration

  public var registrationSuccessful: Bool {
    get {
      return self.persister.hasData(Constants.dataPrefix + Constants.clientIDTag) && self.persister.hasData(Constants.dataPrefix + Constants.pubKeyIDTag)
    }
  }

  private func verifyRegistration(completion: (@escaping ErrorHandler)) {
    // Error on not registered
    if !self.registrationSuccessful {
      completion(PeacemakrError.registrationError)
      return
    }
    // Rotate my keypair if necessary
    self.keyManager.rotateClientKeyIfNeeded(rand: self.rand, completion: { (err) in
      if err != nil {
        completion(err)
      }
      completion(nil)
    })
  }

  public func register(completion: (@escaping ErrorHandler)) {
    if (self.testingMode) {
      Logger.error("Using local-only testing mode!")
      let _ = self.persister.storeData(Constants.dataPrefix + Constants.clientIDTag, val: "my-client-id")
      let _ = self.persister.storeData(Constants.dataPrefix + Constants.pubKeyIDTag, val: "my-pub-key-id")

      guard let _ = try? self.keyManager.createAndStoreKeyPair(with: rand, keyType: "ec", keyLen: 256) else {
        completion(PeacemakrError.keyCreationError)
        return
      }

      completion(nil)
      return
    }

    // First we have to sync the org and config info
    self.syncHandler.syncOrgInfo(apiKey: self.apiKey) { (err) in
      if err != nil {
        completion(err)
      }

      self.syncHandler.syncCryptoConfig(completion: { (err) in
        if err != nil {
          completion(err)
        }

        self.registerToPeacemakr(completion: { completion($0) })
      })
    }
  }

  private func registerToPeacemakr(completion: (@escaping ErrorHandler)) {
    guard let keyType: String = self.persister.getData(Constants.dataPrefix + Constants.clientKeyType) else {
      completion(PeacemakrError.keyConfigurationError)
      return
    }

    guard let keyLen: Int = self.persister.getData(Constants.dataPrefix + Constants.clientKeyLen) else {
      completion(PeacemakrError.keyConfigurationError)
      return
    }

    guard let keyPair = try? self.keyManager.createAndStoreKeyPair(with: rand, keyType: keyType, keyLen: keyLen) else {
      completion(PeacemakrError.keyCreationError)
      return
    }

    guard let orgID: String = self.persister.getData(Constants.dataPrefix + Constants.orgID) else {
      completion(PeacemakrError.registrationError)
      return
    }

    // Call up to server and register myself
    let pubKeyToSend = PublicKey(_id: "", creationTime: Int(Date().timeIntervalSince1970), keyType: keyType, encoding: "pem", key: keyPair.pub.toString(), owningClientId: nil, owningOrgId: orgID)

    let registerClient = Client(_id: "", sdk: version, preferredPublicKeyId: nil, publicKeys: [pubKeyToSend])

    let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)

    requestBuilder.execute({ (resp, error) in
      Logger.info("registration request completed")
      if error != nil {
        Logger.error("addClient failed with " + error.debugDescription)
        completion(error)
        return
      }

      guard let response = resp, let body = response.body else {
        Logger.error("server error: response body was nil")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }

      // Store the clientID and publicKeyID
      guard self.persister.storeData(Constants.dataPrefix + Constants.clientIDTag, val: body._id),
        self.persister.storeData(Constants.dataPrefix + Constants.pubKeyIDTag, val: body.publicKeys.first?._id) else {
        Logger.error("failed to store key pair")
        completion(NSError(domain: "could not store metadata", code: -2, userInfo: nil))
        return
      }

      Logger.info("registered new iOS client: " + Metadata.shared.getClientId(persister: self.persister))
      completion(nil)
    })
  }

  /// MARK: - Sync

  public func sync(completion: (@escaping ErrorHandler)) -> Void {
    if (self.testingMode) {
      Logger.error("No sync ocurred, using local-only testing mode!")
      completion(nil)
      return
    }

    self.verifyRegistration(completion: { (err) in
      self.syncHandler.syncOrgInfo(apiKey: self.apiKey) { (err) in
        if err != nil {
          completion(err)
        }

        self.syncHandler.syncCryptoConfig(completion: { (err) in
          if err != nil {
            completion(err)
          }

          self.syncHandler.syncSymmetricKeys(keyIDs: nil, completion: { completion($0) })
        })
      }
    })
  }


  private func getSymmKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig, completion: (@escaping (PeacemakrKey?, Error?) -> Void)) -> Void {
    let symmKey = self.keyManager.getLocalKeyByID(keyID: keyID, cfg: cfg)
    if symmKey != nil {
      completion(symmKey, nil)
      return
    }

    // If we don't have the key already, re-sync and call the completion callback when we're done
    self.verifyRegistration(completion: { (err) in
      self.syncHandler.syncSymmetricKeys(keyIDs: [keyID], completion: { (err) in
        if err != nil {
          completion(nil, err)
          return
        }

        let downloadedKey = self.keyManager.getLocalKeyByID(keyID: keyID, cfg: cfg)
        if downloadedKey == nil {
          completion(nil, NSError(domain: "Could not get key " + keyID + " from storage after synchronizing keys", code: -17, userInfo: nil))
        }

        completion(downloadedKey, nil)
      })
    })
  }

  /// MARK: - Encryption

  public func encrypt(plaintext: Data) -> Peacemakr.PeacemakrDataResult {
    return encrypt(plaintext)
  }
  
  public func encrypt(in domain: String, plaintext: Data)  -> Peacemakr.PeacemakrDataResult {
    return encrypt(plaintext, useDomainName: domain)
  }
  
  private func encrypt(_ rawMessageData: Data, useDomainName: String? = nil) -> (data: Data?, error: Error?) {
    guard let aadAndKey = self.keyManager.getEncryptionKey(useDomainName: useDomainName ?? ""),
    let aadData = aadAndKey.aad.data(using: .utf8) else {
      return (nil, NSError(domain: "Unable to get the encryption key", code: -101, userInfo: nil))
    }
    let p = Plaintext(data: rawMessageData, aad: aadData)

    guard let encrypted = UnwrapCall(CryptoContext.encrypt(
        key: aadAndKey.key,
        plaintext: p,
        rand: self.rand
    ), onError: Logger.onError) else {
      Logger.error("encryption failed")
      return (nil, PeacemakrError.encryptionError)
    }

    var encCiphertext = encrypted

    guard let signKey = self.keyManager.getMyKey(priv: true) else {
      Logger.error("failed to get my private key")
      return (nil, PeacemakrError.keyManagerError)
    }

    let success = CryptoContext.sign(senderKey: signKey, plaintext: p, digest: aadAndKey.digest, ciphertext: &encCiphertext)
    if !success {
      Logger.error("Signing failed")
      return (nil, PeacemakrError.signingError)
    }

    guard let serialized = UnwrapCall(CryptoContext.serialize(aadAndKey.digest, encCiphertext), onError: Logger.onError) else {
      Logger.error("Serialization failed")
      return (nil, PeacemakrError.serializationError)
    }

    return (serialized, nil)
  }


  /// MARK: - Decryption

  public func decrypt(ciphertext: Data, completion: (@escaping (PeacemakrDataResult) -> Void)) {
    return decrypt(ciphertext, completion: completion)
  }

  private func decrypt(_ serialized: Data, completion: (@escaping (PeacemakrDataResult) -> Void)) {

    guard let keyIDs = try? self.keyManager.getKeyID(serialized: serialized) else {
      Logger.error("Unable to parse key IDs from message")
      completion((nil, PeacemakrError.blobUnwrapError))
      return
    }

    guard let deserializedCfg = UnwrapCall(CryptoContext.deserialize(serialized), onError: Logger.onError) else {
      Logger.error("Unable to deserialize encrypted message")
      completion((nil, PeacemakrError.deserializationError))
      return
    }
    var (deserialized, cfg) = deserializedCfg

    // Get the key specified by the message
    getSymmKeyByID(keyID: keyIDs.keyID, cfg: cfg, completion: { (key, err) in

      if err != nil {
        Logger.error("Trying to get the symmetric key: " + err!.localizedDescription)
        completion((nil, err))
        return
      }
      guard let symmKey = key else {
        completion((nil, PeacemakrError.keyFetchError))
        return
      }

      // Then decrypt
      guard let decryptResult = UnwrapCall(CryptoContext.decrypt(key: symmKey, ciphertext: deserialized), onError: Logger.onError) else {
        completion((nil, PeacemakrError.decryptionError))
        return
      }

      let (outPlaintext, needsVerify) = decryptResult
      // And verify (which is another callback)
      if needsVerify {
        // Quick escape if we're testing locally
        if (keyIDs.signKeyID == "my-pub-key-id" && self.testingMode) {
          completion((outPlaintext.encryptableData, nil))
          return
        }

    
        self.keyManager.getPublicKeyByID(keyID: keyIDs.signKeyID, completion: { (verifyKey) in
          guard let key = verifyKey else {
            completion((nil, PeacemakrError.keyManagerError))
            return
          }
          if !Utilities.verifyMessage(plaintext: outPlaintext, ciphertext: &deserialized, verifyKey: key) {
            completion((nil, PeacemakrError.verificationError))
            return
          }
          completion((outPlaintext.encryptableData, nil))
        })
      } else {
        completion((outPlaintext.encryptableData, nil))
      }
    })
  }

}
