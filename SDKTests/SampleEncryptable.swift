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
  
  fileprivate func toByteArray(i: UInt32) -> [UInt8] {
    var bigEndian = i.bigEndian
    let count = MemoryLayout<UInt32>.size
    let bytePtr = withUnsafePointer(to: &bigEndian) {
      $0.withMemoryRebound(to: UInt8.self, capacity: count) {
        UnsafeBufferPointer(start: $0, count: count)
      }
    }
    return Array(bytePtr)
  }
  
  fileprivate func fromByteArray(array: [UInt8]) -> UInt32 {
    return UInt32(bigEndian: array.withUnsafeBufferPointer {
      ($0.baseAddress!.withMemoryRebound(to: UInt32.self, capacity: 1) { $0 })
      }.pointee)
  }
  
  var Data: [UInt8] {
    get {
      var out = [UInt8](repeating: 0x31, count: 1)
      for key in someOtherProperty {
        out.append(contentsOf: toByteArray(i: UInt32(key.key.count)))
        out.append(contentsOf: key.key.utf8)
        out.append(contentsOf: toByteArray(i: UInt32(key.value.count)))
        out.append(contentsOf: key.value.utf8)
      }
      return out
    }
    set(serialized) {
      if serialized[0] != 0x31 {
        print("Bad magic number deserializing data")
        return
      }
      
      var currentPtr = 1
      let fieldSizeCount = MemoryLayout<UInt32>.size
      var currentFieldSize: UInt32 = 0
      var key: String
      var value: String
      while currentPtr < serialized.count {
        currentFieldSize = fromByteArray(array: Array(serialized[currentPtr..<fieldSizeCount]))
        currentPtr += fieldSizeCount
        key = String(
          bytes: serialized[currentPtr..<(currentPtr + Int(currentFieldSize))],
          encoding: String.Encoding.utf8
        )!
        currentPtr += Int(currentFieldSize)
        
        currentFieldSize = fromByteArray(array: Array(serialized[currentPtr..<(currentPtr + fieldSizeCount)]))
        currentPtr += fieldSizeCount
        value = String(
          bytes: serialized[currentPtr..<(currentPtr + Int(currentFieldSize))],
          encoding: String.Encoding.utf8
        )!
        currentPtr += Int(currentFieldSize)
        
        someOtherProperty[key] = value
      }
    }
  }
  
  var AAD: [UInt8] {
    get {
      var out = [UInt8](repeating: 0x31, count: 1)
      out.append(contentsOf: toByteArray(i: UInt32(someProperty!.count)))
      out.append(contentsOf: someProperty!.utf8)
      return out
    }
    set(serialized) {
      if serialized[0] != 0x31 {
        print("Bad magic number deserializing aad")
        return
      }
      var currentPtr = 1
      let fieldSizeCount = MemoryLayout<UInt32>.size
      let currentFieldSize = fromByteArray(array: Array(serialized[currentPtr..<fieldSizeCount]))
      currentPtr += fieldSizeCount
      someProperty = String(bytes: serialized[currentPtr..<Int(currentFieldSize)], encoding: String.Encoding.utf8)!
    }
  }
    
}
