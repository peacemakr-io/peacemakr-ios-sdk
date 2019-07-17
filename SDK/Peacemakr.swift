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

    
    var localizedDescription: String {
      switch self {
      case .initializationError:
        return "failed to initialize Peacemakr SDK"
      case .registrationError:
        return "failed to register to Peacemakr"
      case .keyManagerError:
        return "faild to access keys"
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
  
  private var apiKey: String = ""
  
  /// MARK: - Initializers

  required public init(apiKey: String, logLevel: Logger.Level) throws {

    if !CryptoContext.setup() {
      throw PeacemakrError.initializationError
    }
    
    Logger.setup(logLevel)

//    self.apiKey = apiKey

    self.rand = PeacemakrRandomDevice()

    // TODO: move to configuration file
//    SwaggerClientAPI.basePath = SwaggerClientAPI.basePath.replacingOccurrences(of: "http", with: "https")
    
    SwaggerClientAPI.basePath = "http://localhost:8080/api/v1"
    OrgAPI.getTestOrganizationAPIKey { (key, err) in
      if err != nil {
        Logger.error("Faild to get test org \(err!.localizedDescription)")
      }
      
      if let testApiKey = key {
        self.apiKey = testApiKey.key
        SwaggerClientAPI.customHeaders = ["Authorization": self.apiKey]
      }
    }
    SwaggerClientAPI.customHeaders = ["contentType": "application/json"]
    SwaggerClientAPI.customHeaders = ["accept": "application/json"]
  }
  
  /// MARK: - Registration

  public var registrationSuccessful: Bool {
    get {
      return Persister.hasData(Constants.dataPrefix + Constants.clientIDTag) && Persister.hasData(Constants.dataPrefix + Constants.pubKeyIDTag)
    }
  }
  
  public func register(completion: (@escaping ErrorHandler)) {
    registerToPeacemakr(completion: completion)
    
  }
  
  private func registerToPeacemakr(completion: (@escaping ErrorHandler)) {

    guard let keyPair = try? KeyManager.createAndStoreKeyPair(with: rand) else {
      completion(PeacemakrError.registrationError)
      return
    }

    // Call up to server and register myself
    let pubKeyToSend = PublicKey(_id: "", creationTime: Int(Date().timeIntervalSince1970), keyType: "rsa", encoding: "pem", key: keyPair.pub.toString(), owningClientId: nil, owningOrgId: nil)

    let registerClient = Client(_id: "", sdk: version, preferredPublicKeyId: nil, publicKeys: [pubKeyToSend])

    let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)

    requestBuilder.execute({ (resp, error) in
      Logger.info("registration request completed")
      if error != nil {
        Logger.error("addClient failed with " + error!.localizedDescription )
        completion(error)
        return
      }

      guard let response = resp, let body = response.body else {
        Logger.error("server error")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }

      // Store the clientID
      Persister.storeData(Constants.dataPrefix + Constants.clientIDTag, val: body._id)
      
      // We only sent up one public key,
      // but just in case the server has some other state we use the last one
      if let idxOfPreferredPublicKey = body.publicKeys.firstIndex(where: {
                                        $0._id == body.preferredPublicKeyId
      }) {
        // Store the public key ID
        Persister.storeData(Constants.dataPrefix + Constants.pubKeyIDTag, val: body.publicKeys[idxOfPreferredPublicKey]._id)
      }
      

      Logger.info("registered new iOS client: " + Metadata.shared.clientId)
      completion(nil)
    })
  }

  /// MARK: - Sync
  
  public func sync(completion:  (@escaping ErrorHandler)) -> Void {
    SyncHandler.syncOrgInfo(apiKey: self.apiKey) { (err) in
      if err != nil {
        completion(err)
      }

      SyncHandler.syncCryptoConfig(completion: { (err) in
        if err != nil {
          completion(err)
        }

        SyncHandler.syncSymmetricKeys(completion: {completion($0)})
      })
    }
  }

  
  private func getSymmKeyByID(keyID: String, cfg: CoreCrypto.CryptoConfig, completion: (@escaping (PeacemakrKey?, Error?) -> Void)) -> Void {
    let symmKey = KeyManager.getLocalKeyByID(keyID: keyID, cfg: cfg)
    if symmKey != nil {
      completion(symmKey, nil)
      return
    }

    // If we don't have the key already, re-sync and call the completion callback when we're done
    SyncHandler.syncSymmetricKeys(completion: { (err) in
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
  }
  
  /// MARK: - Encryption

  public func encrypt(plaintext: String) -> Peacemakr.PeacemakrStrResult {
    guard let plntxt = plaintext.data(using: .utf8) else {
      return (nil, NSError(domain: "Encryption failed", code: -103, userInfo: nil))
    }
    
    let result = encrypt(plntxt)
    
    if let error = result.error {
      return (nil, error)
    }
    
    if let ciphertext = result.data {
      return (ciphertext.toString(), nil)
    }
    else {
      return (nil,nil)
    }
  }
  
  public func encrypt(plaintext: Data) -> Peacemakr.PeacemakrDataResult {
    return encrypt(plaintext)
  }
  
  public func encrypt(in domain: String, plaintext: String)  -> Peacemakr.PeacemakrStrResult {
    guard let plntxt = plaintext.data(using: .utf8) else {
      return (nil, NSError(domain: "Encryption failed", code: -103, userInfo: nil))
    }
    
    let result = encrypt(plntxt, useDomainID: domain)
    
    if let error = result.error {
      return (nil, error)
    }
    
    if let ciphertext = result.data {
      return (ciphertext.toString(), nil)
    } else {
      return (nil,nil)
    }
  }
  
  public func encrypt(in domain: String, plaintext: Data)  -> Peacemakr.PeacemakrDataResult {
    return encrypt(plaintext, useDomainID: domain)
  }
  
  private func encrypt(_ rawMessageData: Data, useDomainID: String? = nil) -> (data: Data?, error: Error?) {
    guard let aadAndKey = KeyManager.getEncryptionKey(useDomainID: useDomainID ?? ""),
    let aadData = aadAndKey.aad.data(using: .utf8) else {
      return (nil, NSError(domain: "Unable to get the encryption key", code: -101, userInfo: nil))
    }
    let p = Plaintext(data: rawMessageData, aad: aadData)

    guard let encrypted = UnwrapCall(CryptoContext.encrypt(
      recipientKey: aadAndKey.key,
      plaintext: p,
      rand: self.rand
    ), onError: Logger.onError) else {
      Logger.error("encryption failed")
      return (nil, NSError(domain: "Encryption failed", code: -103, userInfo: nil))
    }

    var encCiphertext = encrypted

    guard let signKey = KeyManager.getMyKey(priv: true) else {
      Logger.error("failed to get my private key")
      return (nil, NSError(domain: "Unable to get my private key", code: -104, userInfo: nil))
    }

    // TODO: digest alg should come from config or fall back to default sha 512 or sha 256
    CryptoContext.sign(recipientKey: signKey, plaintext: p, digest: .SHA_256, ciphertext: &encCiphertext)

    guard let serialized = UnwrapCall(CryptoContext.serialize(.SHA_256, encCiphertext), onError: Logger.onError) else {
      Logger.error("Serialization failed")
      return (nil, NSError(domain: "Serialization failed", code: -105, userInfo: nil))
    }

    return (serialized, nil)
  }


  /// MARK: - Decryption
  
  public func decrypt(ciphertext: Data, completion: (@escaping (PeacemakrDataResult) -> Void)) {
    return decrypt(ciphertext, completion: completion)
  }
  
  public func decrypt(ciphertext: String, completion: (@escaping (PeacemakrStrResult) -> Void)) {
    guard let data = ciphertext.data(using: .utf8) else {
      completion((nil,  NSError(domain: "Decryption failed", code: -107, userInfo: nil)))
      return
    }
    decrypt(data) { result in
      if let error = result.error {
        completion((nil, error))
        return
      }
      
      if let decrypted = result.data {
        completion((decrypted.toString(), nil))
      }
    }
  }
  
  private func decrypt(_ serialized: Data, completion: (@escaping (PeacemakrDataResult) -> Void)) {

    guard let keyIDs = try? KeyManager.getKeyID(serialized: serialized) else {
      Logger.error("Unable to parse key IDs from message")
      completion((nil, NSError(domain: "Unable to get key id", code: -106, userInfo: nil)))
      return
    }
    
    guard let deserializedCfg = UnwrapCall(CryptoContext.deserialize(serialized), onError: Logger.onError) else {
      completion((nil, NSError(domain: "Unable to desirialize data", code: -106, userInfo: nil)))
      Logger.error("Unable to deserialize encrypted message")
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
        completion((nil, NSError(domain: "Unable to get symmetric decrypt key", code: -106, userInfo: nil)))
        return
      }

      // Then decrypt
      guard let decryptResult = UnwrapCall(CryptoContext.decrypt(recipientKey: symmKey, ciphertext: deserialized), onError: Logger.onError) else {
        completion((nil, NSError(domain: "Decryption failed", code: -107, userInfo: nil)))
        return
      }

      let (outPlaintext, needsVerify) = decryptResult
      // And verify (which is another callback)
      if needsVerify {
        KeyManager.getPublicKeyByID(keyID: keyIDs.signKeyID, completion: { (verifyKey) in
          guard let verifyKey = key else {
            completion((nil, PeacemakrError.keyManagerError))
            return
          }
          Utilities.verifyMessage(plaintext: outPlaintext, ciphertext: &deserialized, verifyKey: verifyKey, completion: { (verified) in
            if !verified {
              completion((nil, NSError(domain: "Verification failed", code: -108, userInfo: nil)))
              return
            }
            completion((outPlaintext.encryptableData, nil))
          })
        })
      } else {
        completion((outPlaintext.encryptableData, nil))
      }
    })
  }

}
