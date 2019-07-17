//
//  PeacemakrProtocol.swift
//  Peacemakr-iOS
//
//  Created by Yuliia Synytsia on 5/11/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation

/// Peacemakr SDK Protocol
public protocol PeacemakrProtocol {
  
  /// Completion Handlers
  typealias ErrorHandler = (Error?) -> Void
  typealias PeacemakrStrResult = (data: String?, error: Error?)
  typealias PeacemakrDataResult = (data: Data?, error: Error?)
  
  
  /// SDK version number
  var version: String { get }
  
  // NOTE: what is out API key format and how to get it?
  /// Initializes Peacemakr SDK
  ///
  /// - Parameter apiKey: API
  /// - Throws: on initialization failure
  init(apiKey: String, logLevel: Logger.Level) throws
  
  /**
   Registers to PeaceMakr as a client.
   
   The persister is used to detect prior registrations on this client, so safe to call multiple times. Once a successful invocation of Register is executed once, subsequent calls become a noop. One successful call is required before any cryptographic use of this SDK. Successful registration returns a nil error.
   Registration may fail with invalid apiKey, missing network connectivity, or an invalid persister. On failure, take corrections action and invoke again.
   
   - Parameter competion: error handler
   */
  func register(completion: (@escaping ErrorHandler))
  
  /// MARK: - Encryption
  
  /**
   Encrypt the plaintext.
   
   Restrict which keys may be used to a Use Domain of this specific name. Names of Use Domains are not unique, and this non-unique property of your Organization's Use Domains allows for graceful rotation of encryption keys off of old (retiring, stale, or compromised) Use Domains, simply by creating a new Use Domain with the same name. The transitional purity, both Use Domains may be selected for encryption use by clients restricted to one particular name. Then, retiring of one of the two Use Domains is possible without disrupting your deployed application.
   
   - Parameters:
         - plaintext: text to encrypt
         - in: domain ID
   - Returns: a b64 encoded ciphertext blob on success, else returns a non-nil error.
   */
  func encrypt(plaintext: String) -> PeacemakrStrResult
  
  func encrypt(plaintext: Data) -> PeacemakrDataResult
  
  func encrypt(in domain: String, plaintext: String) -> PeacemakrStrResult
  
  func encrypt(in domain: String, plaintext: Data) -> PeacemakrDataResult
  
  /// MARK: - Decryption
  
  /// Decrypt the ciphertexts. Returns original plaintext on success, else returns a non-nil error.
  ///
  /// - Parameters:
  ///     - serialized: data.
  ///     - dest: Encryptable type
  ///     - completion: Encryptable
  /// - Returns: closure Encryptable
  func decrypt(ciphertext: String, completion: (@escaping (PeacemakrStrResult) -> Void))
  
  func decrypt(ciphertext: Data, completion: (@escaping (PeacemakrDataResult) -> Void))
  
  /// MARK: - Utilities
  /// Synchronizes org info, crypto config and keys
  ///
  /// - Returns: error is sync failed
  func sync(completion: (@escaping ErrorHandler))
  
}
