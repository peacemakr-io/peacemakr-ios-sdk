//
//  SampleEncryptable.swift
//  Peacemakr-iOS
//
//  Created by Aman LaChapelle on 11/4/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import Foundation

enum SerializationError: Error {
  case badMagicNumber
}

class AppData: Encryptable, Equatable {
  var serializedValue = [UInt8]()
  
  private var someProperty: String? = nil
  private var someOtherProperty = [String: String]()
  
  init() {}
  
  static func ==(lhs: AppData, rhs: AppData) -> Bool {
    var out = lhs.someProperty == rhs.someProperty
    out = out && (lhs.someOtherProperty.count == rhs.someOtherProperty.count)
    if out {
      for (kLHS, kRHS) in zip(lhs.someOtherProperty, rhs.someOtherProperty) {
        out = out && (kLHS.key == kRHS.key)
        out = out && (kLHS.value == kRHS.value)
      }
    }
    return out
  }
  
  func setSomeProperty(prop: String) -> Void {
    someProperty = prop
  }
  
  func setSomeOtherProperty(key: String, value: String) -> Void {
    someOtherProperty[key] = value
  }
  
  func onError(error: Error) {
    NSLog(error.localizedDescription)
  }
  
  var EncryptableData: [UInt8] {
    get {
      let jsonEncoder = JSONEncoder()
      let out = try? jsonEncoder.encode(someOtherProperty)
      return [UInt8](out!)
    }
    set(serialized) {
      let jsonDecoder = JSONDecoder()
      someOtherProperty = try! jsonDecoder.decode(Dictionary<String, String>.self, from: Data(serialized))
    }
  }
  
  var AuthenticatableData: [UInt8] {
    get {
      let out = Data(someProperty!.utf8)
      return [UInt8](out)
    }
    set(serialized) {
      someProperty = String(bytes: serialized, encoding: .utf8)
    }
  }
    
}
