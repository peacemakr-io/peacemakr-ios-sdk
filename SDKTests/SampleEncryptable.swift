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

class AppData: Codable, Encryptable, Equatable {
  
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
  
  var serializedValue: [UInt8] {
    get {
      let out = try? JSONEncoder().encode(self)
      if out == nil {
        return [UInt8]()
      }
      return [UInt8](out!)
    }
    set(serialized) {
      let data = try? JSONDecoder().decode(AppData.self, from: Data(bytes: serialized))
      if data == nil {
        NSLog("Failed to decode data")
      }
      
      self.someProperty = data!.someProperty
      self.someOtherProperty = data!.someOtherProperty
    }
  }
    
}
