//
//  SDKTests.swift
//  SDKTests
//
//  Created by Aman LaChapelle on 11/4/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import XCTest
@testable import Peacemakr

class SDKTests: XCTestCase {
  var sdk: PeacemakrSDK? = nil
  var data: AppData? = nil

  override func setUp() {
    do {
      sdk = try PeacemakrSDK()
      try sdk!.Register()
      try sdk!.PreLoad()
    } catch {
      XCTAssert(false, "Initialization of the SDK failed")
    }
    
    data = AppData()
    data?.setSomeProperty(prop: "something")
    data?.setSomeOtherProperty(key: "someKey", value: "someValue")
  }

  override func tearDown() {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
  }

  func testExample() throws {
    let encrypted = try? sdk?.Encrypt(data!, sign: true)
    if encrypted == nil {
      XCTAssert(false, "Encryption failed")
    }
    var outData: Encryptable = AppData()
    try sdk?.Decrypt(encrypted!!, dest: &outData)
    
    XCTAssert(data! == (outData as! AppData))
  }

  func testPerformanceExample() {
      // This is an example of a performance test case.
      self.measure {
        let encrypted = try? sdk?.Encrypt(data!, sign: true)
        if encrypted == nil {
          XCTAssert(false, "Encryption failed")
        }
        var outData: Encryptable = AppData()
        try? sdk?.Decrypt(encrypted!!, dest: &outData)
        
        XCTAssert(data! == (outData as! AppData))
        }
  }

}
