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
  func storeData<T: Codable>(key: String, val: T) -> Bool
  func getData<T: Codable>(key: String) -> T?
}

class DefaultPersister: Persister {
  let log: (String) -> Void
  
  init(logHandler: @escaping (String) -> Void) {
    log = logHandler
  }
  
  func storeKey(_ key: Data, keyID: String) -> Bool {
    let delStatus = SecItemDelete([kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: keyID] as CFDictionary)
    if delStatus != errSecSuccess && delStatus != errSecItemNotFound {
      if #available(iOS 11.3, *) {
        self.log("Failed to clear out keychain entry for keyID: " + keyID + " with error " + String(delStatus) + " - " + (SecCopyErrorMessageString(delStatus, nil)! as String))
      } else {
        self.log("Failed to clear out keychain entry for keyID: " + keyID + " with error " + String(delStatus))
      }
      return false
    }
    
    let keyQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: keyID,
                                    kSecValueData as String: key]
    let addStatus = SecItemAdd(keyQuery as CFDictionary, nil)
    if addStatus != errSecSuccess {
      if #available(iOS 11.3, *) {
        self.log("Failed to add keychain entry for keyID: " + keyID + " with error " + String(delStatus) + " - " + (SecCopyErrorMessageString(delStatus, nil)! as String))
      } else {
        self.log("Failed to add keychain entry for keyID: " + keyID + " with error " + String(delStatus))
      }
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
      self.log("unable to get key " + keyID + " from keychain")
      return nil
    }
    
    return item as? Data
  }
  
  func storeData<T: Codable>(key: String, val: T) -> Bool {
    let userDefaults = UserDefaults.standard
    userDefaults.set(val, forKey: key)
    return userDefaults.synchronize()
  }
  
  func getData<T: Codable>(key: String) -> T? {
    let userDefaults = UserDefaults.standard
    if !userDefaults.synchronize() {
      self.log("unable to syncronize user defaults, may be unable to get item")
    }
    return userDefaults.object(forKey: key) as? T
  }
}
