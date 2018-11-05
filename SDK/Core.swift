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
  private let cryptoContext: CryptoContext
  private var key: PeacemakrKey
  private var rand: RandomDevice
  private var cfg: CryptoConfig
  
  public init() throws {
    cryptoContext = try CryptoContext()
    cfg = CryptoConfig(
      mode: EncryptionMode.SYMMETRIC,
      symm_cipher: SymmetricCipher.CHACHA20_POLY1305,
      asymm_cipher: AsymmetricCipher.NONE,
      digest: MessageDigestAlgorithm.SHA3_512
    )
    rand = PeacemakrRandomDevice()
    key = try PeacemakrKey(config: cfg, rand: rand)
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
    return try cryptoContext.Encrypt(
      key: key,
      plaintext: Plaintext(data: plaintext.EncryptableData, aad: plaintext.AuthenticatableData),
      rand: rand
    )
  }
  
  /**
   Deserializes and decrypts \p serialized and stores the output into \p dest.
   Throws an error on failure of deserialization or decryption.
   */
  public func Decrypt(_ serialized: [UInt8], dest: inout Encryptable) throws -> Void {
    let outPlaintext = try cryptoContext.Decrypt(key: key, serialized: serialized)
    dest.EncryptableData = outPlaintext.EncryptableData
    dest.AuthenticatableData = outPlaintext.AuthenticatableData
  }
  
}
