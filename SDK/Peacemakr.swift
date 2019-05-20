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

    
    var localizedDescription: String {
      switch self {
      case .initializationError:
        return "failed to initialize Peacemakr SDK"
      case .registrationError:
        return "failed to register to Peacemakr"
      }
    }
  }
  
  /// Peacemakr iOS SDK version number
  public var version: String {
    return Metadata.shared.version
  }
  
  /// MARK: - CoreCrypto
  
  private let cryptoContext: CryptoContext
  private var rand: RandomDevice
  
  /// MARK: - Properties
  
  private let apiKey: String
  
  /// MARK: - Initializers

  // throw instaed of return Optional
  // pros of throwing exception: sdk can pass very specific message about an error
  public init(apiKey: String) throws {

    guard let cryptoCtxt = CryptoContext() else {
      throw PeacemakrError.initializationError
    }

    self.apiKey = apiKey

    self.cryptoContext = cryptoCtxt
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
  
  /**
   Registers to PeaceMakr as a client.
   
   The persister is used to detect prior registrations on this client, so safe to call multiple times. Once a successful invocation of Register is executed once, subsequent calls become a noop. One successful call is required before any cryptographic use of this SDK. Successful registration returns a nil error.
   Registration may fail with invalid apiKey, missing network connectivity, or an invalid persister. On failure, take corrections action and invoke again.
   
   - Parameter competion: error handler
   */
  public func register(completion: (@escaping ErrorHandler)) {
    registerToPeacemakr(completion: completion)
    
  }
  
  private func registerToPeacemakr(completion: (@escaping ErrorHandler)) {

    guard let keyPair = try? KeyManager.createAndStoreKeyPair(with: rand) else {
      completion(PeacemakrError.registrationError)
      return
    }

    // Call up to server and register myself
    let pubKeyToSend = PublicKey(_id: "", creationTime: Int(Date().timeIntervalSince1970), keyType: "rsa", encoding: "pem", key: keyPair.pub.toString())

    let registerClient = Client(_id: "", sdk: version, publicKey: pubKeyToSend)

    let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)

    requestBuilder.execute({ (resp, error) in
      Logger.info("registration request completed")
      if error != nil {
        Logger.error("addClient failed with " + error.debugDescription)
        completion(error)
        return
      }

      guard let response = resp, let body = response.body else {
        Logger.error("server error")
        completion(NSError(domain: "response body was nil", code: -34, userInfo: nil))
        return
      }

    // Store the clientID and publicKeyID
     guard Persister.storeData(Constants.dataPrefix + Constants.clientIDTag, val: body._id),
          Persister.storeData(Constants.dataPrefix + Constants.pubKeyIDTag, val: body.publicKey._id) else {
        Logger.error("failed to store key pair")
        completion(NSError(domain: "could not store metadata", code: -2, userInfo: nil))
        return
      }

      Logger.info("registered new iOS client: " + Metadata.shared.clientId)
      completion(nil)
    })
  }

 

  public func sync(completion: (@escaping (Error?) -> Void)) -> Void {
    SyncHandler.syncOrgInfo(apiKey: self.apiKey) { (err) in
      if err != nil {
        completion(err)
      }

      SyncHandler.syncCryptoConfig(completion: { (err) in
        if err != nil {
          completion(err)
        }

        SyncHandler.syncSymmetricKeys(cryptoContext: self.cryptoContext, completion: {completion($0)})
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
    SyncHandler.syncSymmetricKeys(cryptoContext: cryptoContext, completion: { (err) in
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
  
  /**
   Encrypt the plaintext.
   
   Restrict which keys may be used to a Use Domain of this specific name. Names of Use Domains are not unique, and this non-unique property of your Organization's Use Domains allows for graceful rotation of encryption keys off of old (retiring, stale, or compromised) Use Domains, simply by creating a new Use Domain with the same name. The transitional purity, both Use Domains may be selected for encryption use by clients restricted to one particular name. Then, retiring of one of the two Use Domains is possible without disrupting your deployed application.
   
   - Parameter plaintext: text to encrypt
   - Parameter domain: domain ID
   - Returns: a b64 encoded ciphertext blob on success, else returns a non-nil error.
   */
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

    guard let encrypted = UnwrapCall(self.cryptoContext.encrypt(
      key: aadAndKey.key,
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
    self.cryptoContext.sign(senderKey: signKey, plaintext: p, digest: .SHA_256, ciphertext: &encCiphertext)

    guard let serialized = UnwrapCall(self.cryptoContext.serialize(.SHA_256, encCiphertext), onError: Logger.onError) else {
      Logger.error("Serialization failed")
      return (nil, NSError(domain: "Serialization failed", code: -105, userInfo: nil))
    }

    return (serialized, nil)
  }


  /// MARK: - Decryption
  
  /// Decrypt the ciphertexts. Returns original plaintext on success, else returns a non-nil error.
  ///
  /// - Parameters:
  ///     - serialized: data.
  ///     - dest: Encryptable type
  ///     - completion: Encryptable
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

    guard let keyIDs = try? KeyManager.getKeyID(serialized: serialized, cryptoContext: cryptoContext) else {
      Logger.error("Unable to parse key IDs from message")
      completion((nil, NSError(domain: "Unable to get key id", code: -106, userInfo: nil)))
      return
    }
    
    guard let deserializedCfg = UnwrapCall(cryptoContext.deserialize(serialized), onError: Logger.onError) else {
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
      guard let decryptResult = UnwrapCall(self.cryptoContext.decrypt(key: symmKey, ciphertext: deserialized), onError: Logger.onError) else {
        completion((nil, NSError(domain: "Decryption failed", code: -107, userInfo: nil)))
        return
      }

      let (outPlaintext, needsVerify) = decryptResult
      // And verify (which is another callback)
      if needsVerify {
        KeyManager.getPublicKeyByID(keyID: keyIDs.signKeyID, completion: { (verifyKey) in
          Utilities.verifyMessage(plaintext: outPlaintext, ciphertext: &deserialized, verifyKey: verifyKey!, cryptoContext: self.cryptoContext, completion: { (verified) in
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
