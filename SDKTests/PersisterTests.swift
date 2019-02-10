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
  var persister: DefaultPersister? = nil
  
  override func setUp() {
    persister = DefaultPersister(logHandler: { print($0) })
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
    
    XCTAssert(persister!.storeKey(keyData, keyID: keyID))
    
    let gotKeyData = persister!.getKey(keyID)
    XCTAssert(gotKeyData != nil)
    XCTAssert(gotKeyData! == keyData)
  }
  
  func testDatastore() throws {
    let clientID = "some client ID"
    
    XCTAssert(persister!.storeData("clientID", val: clientID))
    XCTAssert(persister!.hasData("clientID"))
    let gotClientID: String? = persister!.getData("clientID")
    XCTAssert(gotClientID != nil)
    XCTAssert(gotClientID! == clientID)
  }
}
