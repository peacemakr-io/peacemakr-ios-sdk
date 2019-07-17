//
//  PersisterTests.swift
//  Peacemakr-iOS
//
//  Created by Aman LaChapelle on 1/29/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import XCTest
@testable import Peacemakr

class PersisterTests: XCTestCase {
  
  override func setUp() {
  }
  
  func testKeystore() throws {
    var keyData = Data(count: 32)
    let result = keyData.withUnsafeMutableBytes {
      (mutableBytes: UnsafeMutablePointer<UInt8>) -> Int32 in
      SecRandomCopyBytes(kSecRandomDefault, 32, mutableBytes)
    }
    XCTAssert(result == errSecSuccess)
    
    print(keyData)
    
    let keyID = "io.peacemakr.client.symmetric.testKey"
    
    XCTAssert(Persister.storeKey(keyData, keyID: keyID))
    
    let gotKeyData = Persister.getKey(keyID)
    XCTAssert(gotKeyData != nil)
    XCTAssert(gotKeyData! == keyData)
  }
  
  func testDatastore() throws {
    let clientID = "some client ID"
    
    XCTAssert(Persister.hasData("clientID"))
    let gotClientID: String? = Persister.getData("clientID")
    XCTAssert(gotClientID != nil)
    XCTAssert(gotClientID! == clientID)
  }
}
