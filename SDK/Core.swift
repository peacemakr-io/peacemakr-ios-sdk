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
  // Private methods and vars
  private let cryptoContext: CryptoContext
  private var key: PeacemakrKey? = nil
  private var myPrivKey: PeacemakrKey? = nil
  private var myPubKey: PeacemakrKey? = nil
  private var rand: RandomDevice
  private var cfg: CryptoConfig? = nil
  private let privateTag = "io.peacemakr.private"
  private let publicTag = "io.peacemakr.public"
  
  private func generateMyRSAKey(_ rsaAlgorithm: AsymmetricCipher) -> Bool {
    var sanityCheck: OSStatus = noErr
    var publicKey: SecKey?
    var privateKey: SecKey?
    // Container dictionaries
    var privateKeyAttr = [AnyHashable : Any]()
    var publicKeyAttr = [AnyHashable: Any]()
    var keyPairAttr = [AnyHashable : Any]()
    // Set top level dictionary for the keypair
    keyPairAttr[(kSecAttrKeyType ) as AnyHashable] = (kSecAttrKeyTypeRSA as Any)
    // Size in bits
    if (rsaAlgorithm == AsymmetricCipher.RSA_2048) {
      keyPairAttr[(kSecAttrKeySizeInBits as AnyHashable)] = 2048
    } else if (rsaAlgorithm == AsymmetricCipher.RSA_4096) {
      keyPairAttr[(kSecAttrKeySizeInBits as AnyHashable)] = 4096
    }
    // Set private key dictionary
    privateKeyAttr[(kSecAttrIsPermanent as AnyHashable)] = Int(true)
    privateKeyAttr[(kSecAttrApplicationTag as AnyHashable)] = privateTag
    // Set public key dictionary.
    publicKeyAttr[(kSecAttrIsPermanent as AnyHashable)] = Int(true)
    publicKeyAttr[(kSecAttrApplicationTag as AnyHashable)] = publicTag
    
    keyPairAttr[(kSecPrivateKeyAttrs as AnyHashable)] = privateKeyAttr
    keyPairAttr[(kSecPublicKeyAttrs as AnyHashable)] = publicKeyAttr
    sanityCheck = SecKeyGeneratePair((keyPairAttr as CFDictionary), &publicKey, &privateKey)
    if sanityCheck != noErr || publicKey == nil || privateKey == nil {
      return false
    }
    
    // Get the keys out of their SecKey objects
//    var extractError:Unmanaged<CFError>?
//
//    // Private key first
//    var privData: Data?
//    if #available(iOS 10.0, *) {
//      privData = SecKeyCopyExternalRepresentation(privateKey!, &extractError) as Data?
//      if (privData == nil) {
//        print("error: ", extractError!.takeRetainedValue() as Error)
//        return false
//      }
//    } else {
//      // Fallback on earlier versions
//    }
//
//    let privKeyConfig = CryptoConfig(mode: EncryptionMode.ASYMMETRIC, symm_cipher: SymmetricCipher.AES_256_GCM, asymm_cipher: rsaAlgorithm, digest: MessageDigestAlgorithm.SHA3_512)
//
//    self.myPrivKey = PeacemakrKey(config: privKeyConfig, fileContents: Array(privData!.base64EncodedString()).map(Int8.init), is_priv: true)
//
//    var pubData: Data?
//    if #available(iOS 10.0, *) {
//      pubData = SecKeyCopyExternalRepresentation(publicKey!, &extractError) as Data?
//      if (pubData == nil) {
//        print("error: ", extractError!.takeRetainedValue() as Error)
//        return false
//      }
//    } else {
//      // Fallback on earlier versions
//    }
//
//    let pubKeyConfig = CryptoConfig(mode: EncryptionMode.ASYMMETRIC, symm_cipher: SymmetricCipher.AES_256_GCM, asymm_cipher: rsaAlgorithm, digest: MessageDigestAlgorithm.SHA3_512)
//
//    self.myPubKey = PeacemakrKey(config: pubKeyConfig, fileContents: Array(pubData!.base64EncodedString()).map(Int8.init), is_priv: false)
    return true
  }
  
  // Public methods and vars
  public init() throws {
    cryptoContext = try CryptoContext()
    rand = PeacemakrRandomDevice()
  }
  
  public func Register() throws {
    // TODO: call up to the server
  }
  
  public func PreLoad() throws {
    // TODO: load up my keys
  }
  
  /**
   Returns an encrypted and base64 serialized blob that contains \p plaintext.
   Throws an error on failure of encryption or serialization.
   */
  public func Encrypt(_ plaintext: Encryptable) throws -> [UInt8] {
    let ptext = Plaintext(data: plaintext.Serialized, aad: [])
    let encrypted = try cryptoContext.Encrypt(
      key: key!,
      plaintext: ptext,
      rand: rand
    )
    
    return try cryptoContext.Serialize(encrypted)
  }
  
  /**
   Deserializes and decrypts \p serialized and stores the output into \p dest.
   Throws an error on failure of deserialization or decryption.
   */
  public func Decrypt(_ serialized: [UInt8], dest: inout Encryptable) throws -> Void {
    let (deserialized, _) = try cryptoContext.Deserialize(serialized)
    
    let (outPlaintext, _) = try cryptoContext.Decrypt(key: key!, ciphertext: deserialized)
    dest.Serialized = outPlaintext.EncryptableData
  }
  
}
