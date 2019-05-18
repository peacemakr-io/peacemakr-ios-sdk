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
  func storeData<T: Codable>(_ key: String, val: T) -> Bool
  func getData<T: Codable>(_ key: String) -> T?
  func hasData(_ key: String) -> Bool
}

class DefaultPersister: Persister {
  
  init() {}
  
  func storeKey(_ key: Data, keyID: String) -> Bool {
    let delStatus = SecItemDelete([kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: keyID] as CFDictionary)
    if delStatus != errSecSuccess && delStatus != errSecItemNotFound {
      if #available(iOS 11.3, *) {
        Logger.error("failed to clear out keychain entry for keyID: " + keyID + " with error " + String(delStatus) + " - " + (SecCopyErrorMessageString(delStatus, nil)! as String))
      } else {
        Logger.error("Failed to clear out keychain entry for keyID: " + keyID + " with error " + String(delStatus))
      }
      return false
    }
    
    let keyQuery: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: keyID,
                                    kSecValueData as String: key]
    let addStatus = SecItemAdd(keyQuery as CFDictionary, nil)
    if addStatus != errSecSuccess {
      if #available(iOS 11.3, *) {
        Logger.error("failed to add keychain entry for keyID: " + keyID + " with error " + String(delStatus) + " - " + (SecCopyErrorMessageString(delStatus, nil)! as String))
      } else {
        Logger.error("failed to add keychain entry for keyID: " + keyID + " with error " + String(delStatus))
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
      Logger.error("failed to get key " + keyID + " from keychain")
      return nil
    }
    
    return item as? Data
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
  
  func hasData(_ key: String) -> Bool {
    let userDefaults = UserDefaults.standard
    return userDefaults.object(forKey: key) != nil
  }
}
