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
  private let version = "0.1.0"
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
  
  private let privTag = "io.peacemakr.client.private"
  private let pubTag = "io.peacemakr.client.public"
  // symmetric keys start with this prefix and append the key ID onto it
  private let symmTagPrefix = "io.peacemakr.client.symmetric."
  
  private struct ClientData: Codable {
    let clientID: String
    let publicKeyID: [UInt8]
  }
  
  private let clientDataURL: URL?
  
  public init?(apiKey: String, logHandler: @escaping (String)->Void) {
    SwaggerClientAPI.basePath = SwaggerClientAPI.basePath.replacingOccurrences(of: "http", with: "https")
    
    self.apiKey = apiKey
    self.logHandler = logHandler
    
    let cc = CryptoContext()
    cryptoContext = cc!
    rand = PeacemakrRandomDevice()
    
    do {
      let docsBaseURL = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
      self.clientDataURL = docsBaseURL.appendingPathComponent("clientData.json", isDirectory: false)
      do {
        if FileManager.default.fileExists(atPath: self.clientDataURL!.path) {
          try FileManager.default.removeItem(at: self.clientDataURL!)
        }
        FileManager.default.createFile(atPath: self.clientDataURL!.path, contents: nil, attributes: nil)
      } catch {
        self.log("Unable to create file at \(self.clientDataURL!)")
        return nil
      }
    } catch {
      self.clientDataURL = nil
      self.log("Unable to get a file URL for client data")
    }
    
    if cc == nil {
      self.log("Unable to init CryptoContext")
      return nil
    }
  }
  
  private func log(_ s: String) -> Void {
    if self.RegistrationSuccessful {
      let logEvent = Log()
      
      logEvent.clientId = getMyClientID()
      logEvent.event = s
      
      let requestBuilder = PhoneHomeAPI.logPostWithRequestBuilder(log: logEvent)
      
      sendRequest(builder: requestBuilder, completion: {(response, error) in
        if error != nil {
          self.logHandler("phonehome request failed")
        }
      })
    }
    
    // Log whether or not the request succeeds
    self.logHandler(s)
  }
  
  // These are async...all of them...
  private func sendRequest<T>(builder: RequestBuilder<T>, completion: @escaping (_ response: T?, _ error: Error?) -> Void) -> Void {
    builder.addHeaders(["authorization": self.apiKey])
    builder.execute({ (response, error) -> Void in
      completion(response?.body, error)
    })
  }
  
  private func storeClientData(_ data: ClientData) -> Bool {
    let encoder = JSONEncoder()
    do {
      let data = try encoder.encode(data)
      try data.write(to: self.clientDataURL!)
    } catch {
      self.log("Unable to write client data to file: " + error.localizedDescription)
      return false
    }
    
    return true
  }
  
  private func getClientData() -> ClientData? {
    if !FileManager.default.fileExists(atPath: self.clientDataURL!.path) {
      self.logHandler("File at path \(self.clientDataURL!.path) does not exist!")
      return nil
    }
    
    if let data = FileManager.default.contents(atPath: self.clientDataURL!.path) {
      let decoder = JSONDecoder()
      do {
        let model = try decoder.decode(PeacemakrSDK.ClientData.self, from: data)
        return model
      } catch let error {
        self.logHandler("Failed to decode ClientData: " + error.localizedDescription)
        return nil
      }
    } else {
      self.logHandler("No data at \(self.clientDataURL!.path)!")
      return nil
    }
  }
  
  public var RegistrationSuccessful: Bool = false
  
  public func Register() -> Bool {
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
    let privPem = priv!
    
    var privPemData: Data? = nil
    privPem.withUnsafeBufferPointer({buf -> Void in
      privPemData = Data(buffer: buf)
    })
    
    let privQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: self.privTag,
                                    kSecValueData as String: privPemData!]
    
    let delPrivStatus = SecItemDelete([kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: self.privTag] as CFDictionary)
    if delPrivStatus != errSecSuccess && delPrivStatus != errSecItemNotFound {
      if #available(iOS 11.3, *) {
        self.log("Failed to clear out keychain (priv): " + String(delPrivStatus) + " - " + (SecCopyErrorMessageString(delPrivStatus, nil)! as String))
      } else {
        self.log("Failed to clear out keychain (priv): " + String(delPrivStatus))
      }
      return false
    }
    
    let privStatus = SecItemAdd(privQuery as CFDictionary, nil)
    if privStatus != errSecSuccess {
      if #available(iOS 11.3, *) {
        self.log("Failed to add private key to keychain: " + String(privStatus) + " - " + (SecCopyErrorMessageString(privStatus, nil)! as String))
      } else {
        self.log("Failed to add private key to keychain: " + String(privStatus))
      }
      return false
    }
    
    // Store public key
    let pub = UnwrapCall(myKey!.toPem(is_priv: false), onError: self.log)
    if pub == nil {
      self.log("pub key to pem failed")
      return false
    }
    let pubPem = pub!
    
    var pubPemData: Data? = nil
    pubPem.withUnsafeBufferPointer({buf -> Void in
      pubPemData = Data(buffer: buf)
    })
    
    let pubQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: self.pubTag,
                                   kSecValueData as String: pubPemData!]
    
    let delPubStatus = SecItemDelete([kSecClass as String: kSecClassKey,
                                      kSecAttrApplicationTag as String: self.pubTag] as CFDictionary)
    if delPubStatus != errSecSuccess && delPubStatus != errSecItemNotFound {
      if #available(iOS 11.3, *) {
        self.log("Failed to clear out keychain (pub): " + String(delPubStatus) + " - " + (SecCopyErrorMessageString(delPubStatus, nil)! as String))
      } else {
        self.log("Failed to clear out keychain (pub): " + String(delPubStatus))
      }
      return false
    }
    
    let pubStatus = SecItemAdd(pubQuery as CFDictionary, nil)
    if pubStatus != errSecSuccess {
      if #available(iOS 11.3, *) {
        self.log("Failed to add public key to keychain: " + String(pubStatus) + " - " + (SecCopyErrorMessageString(pubStatus, nil)! as String))
      } else {
        self.log("Failed to add public key to keychain: " + String(pubStatus))
      }
      return false
    }
    
    // Call up to server and register myself
    let registerClient = Client()
    registerClient.sdk = version
    registerClient.id = "" // will be populated with my client ID by the server
    registerClient.publicKey?.creationTime = Int32(Date().timeIntervalSince1970)
    registerClient.publicKey?.encoding = "pem"
    registerClient.publicKey?.id = "" // will be populated with my public key ID by the server
    registerClient.publicKey?.key = String(cString: pubPem)
    registerClient.publicKey?.keyType = "rsa"
    
    let requestBuilder = ClientAPI.addClientWithRequestBuilder(client: registerClient)
    sendRequest(builder: requestBuilder, completion: {(client, error) in
      if error != nil {
        self.log("addClient failed")
      }
      
      // Store the clientID and publicKeyID
      let clientID = client?.id
      if clientID == nil {
        self.log("Client ID returned was nil")
      }

      let pubKeyID = client?.publicKey?.id
      if pubKeyID == nil {
        self.log("Public key ID returned was nil")
      }

      let clientInfo = ClientData(clientID: clientID!, publicKeyID: Array(pubKeyID!.utf8))
      if !self.storeClientData(clientInfo) {
        self.log("Failed to store client data")
      }
      
      self.RegistrationSuccessful = true
    })
    
    return true
  }
  
  private func getMyClientID() -> String? {
    let clientData = getClientData()
    if clientData == nil {
      self.logHandler("failed to get my client ID from the filesystem")
      return nil
    }
    
    return clientData!.clientID
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
    let tag = symmTagPrefix + keyIDStr!
    
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: tag,
                                kSecValueData as String: Data(bytes: key)]
    
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
      self.log("could not add symmetric key: " + keyIDStr! + " to keychain")
      return false
    }
    
    return true
  }
  
  private func getPublicKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    var outKeyPem: [CChar] = []
    let requestBuilder = KeyServiceAPI.getPublicKeyWithRequestBuilder(keyID: String(bytes: keyID, encoding: .utf8)!)
    sendRequest(builder: requestBuilder, completion: {(key, error) in
      let keyStr = key?.key
      outKeyPem = Array(keyStr!.utf8CString)
    })
    
    return PeacemakrKey(config: cfg, fileContents: outKeyPem, is_priv: false)
  }
  
  private func getLocalKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let keyIDStr = String(bytes: keyID, encoding: .utf8)
    if keyIDStr == nil {
      self.log("Could not marshal keyID to string")
      return nil
    }
    let tag = symmTagPrefix + keyIDStr!
    
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    guard status == errSecSuccess else {
      self.log("could not get symmetric key: " + keyIDStr! + " from keychain")
      return nil
    }
    
    let keyBytes = item as! [UInt8]
    return PeacemakrKey(config: cfg, bytes: keyBytes)
  }
  
  private func getSymmKeyByID(keyID: [UInt8], cfg: CoreCrypto.CryptoConfig) -> PeacemakrKey? {
    let symmKey = getLocalKeyByID(keyID: keyID, cfg: cfg)
    if symmKey != nil {
      return symmKey
    }
    
    // this means that we don't have the key we need, so go up to server and get the key we need
    let myClientID = getMyClientID()
    if myClientID == nil {
      self.log("Unable to get client ID")
      return nil
    }
    
    let requestBuilder = KeyServiceAPI.getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: myClientID!, symmetricKeyIds: [String(bytes: keyID, encoding: .utf8)!])
    let myPrivKey = getMyKey(priv: true)
    var keysInRequest: [EncryptedSymmetricKey] = []
    sendRequest(builder: requestBuilder, completion: {(keys, error) in
      if keys == nil {
        self.log("Get encrypted keys failed")
        return
      }
      keysInRequest = keys!
    })
    
    for key in keysInRequest {
      let serialized = key.packagedCiphertext?.utf8
      if serialized == nil {
        self.log("key package:" + (key.symmetricKeyUseDomainId ?? "unknown") + " ciphertext not present")
        return nil
      }
      
      let storedKeyIDs = getKeyID(serialized: Array(serialized!))
      if storedKeyIDs == nil {
        self.log("Unable to extract key IDs serialized key package")
        return nil
      }
      
      let (_, signKeyID) = storedKeyIDs!
      let deserializedCfg = UnwrapCall(cryptoContext.Deserialize(Array(serialized!)), onError: self.log)
      if deserializedCfg == nil {
        self.log("Unable to deserialize key package ciphertext")
        return nil
      }
      var (deserialized, _) = deserializedCfg!
      
      let decryptResult = UnwrapCall(cryptoContext.Decrypt(key: myPrivKey!, ciphertext: deserialized), onError: self.log)
      if decryptResult == nil {
        self.log("Unable to decrypt key package ciphertext")
        return nil
      }
      
      let (keyPlaintext, needVerify) = decryptResult!
      if needVerify {
        let signKey = getPublicKeyByID(keyID: signKeyID, cfg: myKeyCfg)
        let verified = UnwrapCall(cryptoContext.Verify(senderKey: signKey!, plaintext: keyPlaintext, ciphertext: &deserialized), onError: self.log)
        if verified == nil || verified! == false {
          self.log("Verification of key package failed")
          return nil
        }
      }
      
      guard let keyBytes = Data(base64Encoded: String(bytes: keyPlaintext.EncryptableData, encoding: .utf8)!) else {
        self.log("Invalid b64 key")
        return nil
      }
      
      let keyLen = Int(key.keyLength!)
      let keyIDs = key.keyIds!
      for (i, keyID) in keyIDs.enumerated() {
        let thisKeyBytes = keyBytes[i*keyLen..<(i+1)*keyLen]
        if !storeKey(key: Array(thisKeyBytes), keyID: Array(keyID.utf8)) {
          self.log("Storing key failed")
          return nil
        }
      }
    }
    
    // Try again now that I've gotten the key
    return getSymmKeyByID(keyID: keyID, cfg: cfg)
  }
  
  private func getMyKey(priv: Bool) -> PeacemakrKey? {
    var tag: String
    if priv {
      tag = privTag
    } else {
      tag = pubTag
    }
    
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: tag,
                                   kSecReturnRef as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    guard status == errSecSuccess else {
      self.log("unable to get my key (public/private) from keychain")
      return nil
    }
    
    let keyBytes = item as! [Int8]
    return PeacemakrKey(config: myKeyCfg, fileContents: keyBytes, is_priv: priv)
  }
  
  private func selectEncryptionKey() -> ([UInt8], CoreCrypto.CryptoConfig)? {
    // TODO: actually select the encryption key (requires swagger generated code)
    let cfg = CoreCrypto.CryptoConfig(mode: EncryptionMode.SYMMETRIC, symm_cipher: SymmetricCipher.AES_256_GCM, asymm_cipher: AsymmetricCipher.NONE, digest: MessageDigestAlgorithm.SHA3_512)
    return ([], cfg)
  }
  
  private func getMyPublicKeyID() -> [UInt8]? {
    let clientData = getClientData()
    if clientData == nil {
      self.log("failed to get my public key ID from the filesystem")
      return nil
    }
    
    return clientData!.publicKeyID
  }
  
  /**
   Returns an encrypted and base64 serialized blob that contains \p plaintext.
   Throws an error on failure of encryption or serialization.
   */
  public func Encrypt(_ plaintext: Encryptable) -> [UInt8]? {
    let selectedKey = selectEncryptionKey()
    if selectedKey == nil {
      self.log("Unable to select encryption key")
      return nil
    }
    
    let (keyID, keyCfg) = selectedKey!
    let aadJSON = try? JSONSerialization.data(withJSONObject: ["cryptoKeyID": keyID, "senderKeyID": getMyPublicKeyID()], options: [])
    if aadJSON == nil {
      self.log("Failed to serialize the key IDs to json")
      return nil
    }
    let messageAAD = String(data: aadJSON!, encoding: .utf8)
    
    let ptext = Plaintext(data: plaintext.serializedValue, aad: Array(messageAAD!.utf8))
    
    let key = getSymmKeyByID(keyID: keyID, cfg: keyCfg)
    if key == nil {
      self.log("Unable to get the encryption key: " + String(bytes: keyID, encoding: .utf8)!)
      return nil
    }
    let signKey = getMyKey(priv: true)
    if signKey == nil {
      self.log("Unable to get my private key")
      return nil
    }

    var encrypted = UnwrapCall(cryptoContext.Encrypt(
      key: key!,
      plaintext: ptext,
      rand: rand
    ), onError: self.log)
    if encrypted == nil {
      self.log("Encryption failed")
      return nil
    }
    
    // Sign the message with my key
    cryptoContext.Sign(senderKey: signKey!, plaintext: ptext, ciphertext: &encrypted!)
    
    let serialized = UnwrapCall(cryptoContext.Serialize(encrypted!), onError: self.log)
    if serialized == nil {
      self.log("Serialization failed")
      return nil
    }
    
    return serialized
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
  public func Decrypt(_ serialized: [UInt8], dest: inout Encryptable) -> Bool {
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
    
    let key = getSymmKeyByID(keyID: keyID, cfg: cfg)
    if key == nil {
      self.log("Unable to get symmetric key for decrypting the messaage")
      return false
    }
    
    let decryptResult = UnwrapCall(cryptoContext.Decrypt(key: key!, ciphertext: deserialized), onError: self.log)
    if decryptResult == nil {
      self.log("Decryption failed")
      return false
    }
    
    let (outPlaintext, needsVerify) = decryptResult!
    if needsVerify {
      // the key configs for all clients are the same here
      let signKey = getPublicKeyByID(keyID: signKeyID, cfg: myKeyCfg)
      if signKey == nil {
        self.log("Unable to get the public key for keyID: " + String(bytes: signKeyID, encoding: .utf8)!)
        return false
      }
      
      if !UnwrapCall(cryptoContext.Verify(senderKey: signKey!, plaintext: outPlaintext, ciphertext: &deserialized), onError: self.log)! {
        self.log("Verification failed")
        return false
      }
    }
    
    dest.serializedValue = outPlaintext.EncryptableData
    return true
  }
  
}
