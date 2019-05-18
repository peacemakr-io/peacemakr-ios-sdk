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
  typealias LogHandler = (String) -> Void
  typealias ErrorHandler = (Error?) -> Void
  typealias PeacemakrStrResult = (data: String?, error: Error?)
  typealias PeacemakrDataResult = (data: Data?, error: Error?)
  
  
  /// SDK version number
  var version: String { get }
  
  func register(completion: (@escaping ErrorHandler))
  
  //  func preLoad(completion: (@escaping ErrorHandler))
  
  /// MARK: - Encryption
  
  func encrypt(plaintext: String) -> PeacemakrStrResult
  
  func encrypt(plaintext: Data) -> PeacemakrDataResult
  
  func encrypt(in domain: String, plaintext: String) -> PeacemakrStrResult
  
  func encrypt(in domain: String, plaintext: Data) -> PeacemakrDataResult
  
  /// MARK: - Decryption
  
  func decrypt(ciphertext: String, completion: (@escaping (PeacemakrStrResult) -> Void))
  
  func decrypt(ciphertext: Data, completion: (@escaping (PeacemakrDataResult) -> Void))
  
  /// MARK: - Utilities
  
  //  func getDebugInfo() -> String
  
  //  func releaseMemory()
  
}
