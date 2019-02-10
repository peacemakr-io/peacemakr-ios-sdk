//
//  Persister.swift
//  Peacemakr-iOS
//
//  Created by Aman LaChapelle on 1/29/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation

protocol Persister {
  func storeKey(_ key: Data, keyID: String) -> Bool
  func getKey(_ keyID: String) -> Data?
  func deleteKey(_ keyID: String) -> Void
  func storeData<T: Codable>(_ key: String, val: T) -> Bool
  func getData<T: Codable>(_ key: String) -> T?
  func deleteData(_ key: String) -> Void
  func hasData(_ key: String) -> Bool
}

class DefaultPersister: Persister {
  let log: (PeacemakrError) -> Void
  
  init(logHandler: @escaping (PeacemakrError) -> Void) {
    log = logHandler
  }
  
  func storeKey(_ key: Data, keyID: String) -> Bool {
    let delStatus = SecItemDelete([kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: keyID] as CFDictionary)
    if delStatus != errSecSuccess && delStatus != errSecItemNotFound {
      var error: PeacemakrError
      if #available(iOS 11.3, *) {
        error = PeacemakrError(
          what: "Failed to clear out keychain entry for keyID: " + keyID + " with error " + String(delStatus) + " - " + (SecCopyErrorMessageString(delStatus, nil)! as String),
          subsystem: .Persister,
          shouldSend: false
        )
      } else {
        error = PeacemakrError(
          what: "Failed to clear out keychain entry for keyID: " + keyID + " with error " + String(delStatus),
          subsystem: .Persister,
          shouldSend: false
        )
      }
      
      self.log(error)
      return false
    }
    
    let keyQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: keyID,
                                    kSecValueData as String: key]
    let addStatus = SecItemAdd(keyQuery as CFDictionary, nil)
    if addStatus != errSecSuccess {
      var error: PeacemakrError
      if #available(iOS 11.3, *) {
        error = PeacemakrError(
          what: "Failed to add keychain entry for keyID: " + keyID + " with error " + String(delStatus) + " - " + (SecCopyErrorMessageString(delStatus, nil)! as String),
          subsystem: .Persister,
          shouldSend: false
        )
      } else {
        error = PeacemakrError(
          what: "Failed to add keychain entry for keyID: " + keyID + " with error " + String(delStatus),
          subsystem: .Persister,
          shouldSend: false
        )
      }
      
      self.log(error)
      return false
    }
    
    return true
  }
  
  func getKey(_ keyID: String) -> Data? {
    let getquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: keyID,
                                   kSecReturnData as String: true]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getquery as CFDictionary, &item)
    if status != errSecSuccess {
      let error = PeacemakrError(what: "unable to get key " + keyID + " from keychain", subsystem: .Persister, shouldSend: false)
      self.log(error)
      return nil
    }
    
    return item as? Data
  }
  
  func deleteKey(_ keyID: String) {
    let delStatus = SecItemDelete([kSecClass as String: kSecClassKey,
                                   kSecAttrApplicationTag as String: keyID] as CFDictionary)
    if delStatus != errSecSuccess && delStatus != errSecItemNotFound {
      var error: PeacemakrError
      if #available(iOS 11.3, *) {
        error = PeacemakrError(
          what: "Failed to clear out keychain entry for keyID: " + keyID + " with error " + String(delStatus) + " - " + (SecCopyErrorMessageString(delStatus, nil)! as String),
          subsystem: .Persister,
          shouldSend: false
        )
      } else {
        error = PeacemakrError(
          what: "Failed to clear out keychain entry for keyID: " + keyID + " with error " + String(delStatus),
          subsystem: .Persister,
          shouldSend: false
        )
      }
      
      self.log(error)
      return
    }
    
    return
  }
  
  func storeData<T: Codable>(_ key: String, val: T) -> Bool {
    let userDefaults = UserDefaults.standard
    userDefaults.removeObject(forKey: key)
    userDefaults.set(val, forKey: key)
    return true
  }
  
  func getData<T: Codable>(_ key: String) -> T? {
    let userDefaults = UserDefaults.standard
    return userDefaults.object(forKey: key) as? T
  }
  
  func deleteData(_ key: String) {
    let userDefaults = UserDefaults.standard
    userDefaults.removeObject(forKey: key)
  }
  
  func hasData(_ key: String) -> Bool {
    let userDefaults = UserDefaults.standard
    return userDefaults.object(forKey: key) != nil
  }
}
