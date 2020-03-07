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


    var localizedDescription: String {
      switch self {
      case .initializationError:
        return "failed to initialize Peacemakr SDK"
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

  /// MARK: - Initializers

  required public init(apiKey: String) throws {

    if !CryptoContext.setup() {
      throw PeacemakrError.initializationError
    }

    self.apiKey = apiKey

    self.rand = PeacemakrRandomDevice()

    // TODO: move to configuration file
//    SwaggerClientAPI.basePath = SwaggerClientAPI.basePath.replacingOccurrences(of: "http", with: "https")
    SwaggerClientAPI.basePath = "http://localhost:8080/api/v1"
    SwaggerClientAPI.customHeaders = ["Authorization": self.apiKey]
  }

  /// MARK: - Registration

  public var registrationSuccessful: Bool {
    get {
      return Persister.hasData(Constants.dataPrefix + Constants.clientIDTag) && Persister.hasData(Constants.dataPrefix + Constants.pubKeyIDTag)
    }
  }

  private func verifyRegistration(completion: (@escaping ErrorHandler)) {
    // Error on not registered
    if !self.registrationSuccessful {
      completion(PeacemakrError.registrationError)
      return
    }
    // Rotate my keypair if necessary
    KeyManager.rotateClientKeyIfNeeded(rand: self.rand, completion: { (err) in
      if err != nil {
        completion(err)
      }
    })
  }

  public func register(completion: (@escaping ErrorHandler)) {
    if (self.apiKey.isEmpty) {
      Logger.error("Using local-only testing mode!")
      let _ = Persister.storeData(Constants.dataPrefix + Constants.clientIDTag, val: "my-client-id")
      let _ = Persister.storeData(Constants.dataPrefix + Constants.pubKeyIDTag, val: "my-pub-key-id")

      guard let _ = try? KeyManager.createAndStoreKeyPair(with: rand, keyType: "ec", keyLen: 256) else {
        completion(PeacemakrError.keyCreationError)
        return
      }

      completion(nil)
      return
    }

    // First we have to sync the org and config info
    SyncHandler.syncOrgInfo(apiKey: self.apiKey) { (err) in
      if err != nil {
        completion(err)
      }

      SyncHandler.syncCryptoConfig(completion: { (err) in
        if err != nil {
          completion(err)
        }

        self.registerToPeacemakr(completion: { completion($0) })
      })
    }
  }

  private func registerToPeacemakr(completion: (@escaping ErrorHandler)) {
    guard let keyType: String = Persister.getData(Constants.dataPrefix + Constants.clientKeyType) else {
      completion(PeacemakrError.keyConfigurationError)
      return
    }

    guard let keyLen: Int = Persister.getData(Constants.dataPrefix + Constants.clientKeyLen) else {
      completion(PeacemakrError.keyConfigurationError)
      return
    }

    guard let keyPair = try? KeyManager.createAndStoreKeyPair(with: rand, keyType: keyType, keyLen: keyLen) else {
      completion(PeacemakrError.keyCreationError)
      return
    }

    guard let orgID: String = Persister.getData(Constants.dataPrefix + Constants.orgID) else {
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
      guard Persister.storeData(Constants.dataPrefix + Constants.clientIDTag, val: body._id),
            Persister.storeData(Constants.dataPrefix + Constants.pubKeyIDTag, val: body.publicKeys.first?._id) else {
        Logger.error("failed to store key pair")
        completion(NSError(domain: "could not store metadata", code: -2, userInfo: nil))
        return
      }

      Logger.info("registered new iOS client: " + Metadata.shared.clientId)
      completion(nil)
    })
  }

  /// MARK: - Sync

  public func sync(completion: (@escaping ErrorHandler)) -> Void {
    if (self.apiKey.isEmpty) {
      Logger.error("No sync ocurred, using local-only testing mode!")
      completion(nil)
      return
    }

    self.verifyRegistration(completion: { (err) in
      SyncHandler.syncOrgInfo(apiKey: self.apiKey) { (err) in
        if err != nil {
          completion(err)
        }

        SyncHandler.syncCryptoConfig(completion: { (err) in
          if err != nil {
            completion(err)
          }

          SyncHandler.syncSymmetricKeys(keyIDs: nil, completion: { completion($0) })
        })
      }
    })
  }


  private func getSymmKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig, completion: (@escaping (PeacemakrKey?, Error?) -> Void)) -> Void {
    let symmKey = KeyManager.getLocalKeyByID(keyID: keyID, cfg: cfg)
    if symmKey != nil {
      completion(symmKey, nil)
      return
    }

    // If we don't have the key already, re-sync and call the completion callback when we're done
    self.verifyRegistration(completion: { (err) in
      SyncHandler.syncSymmetricKeys(keyIDs: [keyID], completion: { (err) in
        if err != nil {
          completion(nil, err)
          return
        }

        let downloadedKey = KeyManager.getLocalKeyByID(keyID: keyID, cfg: cfg)
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

  public func encrypt(in domain: String, plaintext: Data) -> Peacemakr.PeacemakrDataResult {
    return encrypt(plaintext, useDomainID: domain)
  }

  private func encrypt(_ rawMessageData: Data, useDomainID: String? = nil) -> (data: Data?, error: Error?) {

    let useDomainToUse = self.apiKey.isEmpty ? "my-local-use-domain-id" : (useDomainID ?? "")
    guard let aadAndKey = KeyManager.getEncryptionKey(useDomainID: useDomainToUse),
          let aadData = aadAndKey.aad.data(using: .utf8) else {
      return (nil, PeacemakrError.keyManagerError)
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

    guard let signKey = KeyManager.getMyKey(priv: true) else {
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

    guard let keyIDs = try? KeyManager.getKeyID(serialized: serialized) else {
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
        if (keyIDs.signKeyID == "my-pub-key-id" && self.apiKey.isEmpty) {
          completion((outPlaintext.encryptableData, nil))
          return
        }

        KeyManager.getPublicKeyByID(keyID: keyIDs.signKeyID, completion: { (verifyKey) in
          guard let verifyKey = key else {
            completion((nil, PeacemakrError.keyManagerError))
            return
          }
          if !Utilities.verifyMessage(plaintext: outPlaintext, ciphertext: &deserialized, verifyKey: verifyKey) {
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
