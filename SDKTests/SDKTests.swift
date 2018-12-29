//
//  SDKTests.swift
//  SDKTests
//
//  Created by Aman LaChapelle on 11/4/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import XCTest
@testable import Peacemakr

func log(_ s: String) -> Void {
  print(s)
}

class SDKTests: XCTestCase {
  var sdk: PeacemakrSDK? = nil
  var data: AppData? = nil

  override func setUp() {
    do {
      sdk = PeacemakrSDK(apiKey: "123-123-123", logHandler: log)
      sdk!.Register()
      sdk!.PreLoad()
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
    let encrypted = try? sdk?.Encrypt(data!)
    if encrypted == nil {
      XCTAssert(false, "Encryption failed")
    }
    var outData: Encryptable = AppData()
    try sdk?.Decrypt(encrypted!!, dest: &outData)
    
    XCTAssert(data! == (outData as! AppData))
  }

  func testPerformanceExample() {
      self.measure {
        let encrypted = try? self.sdk?.Encrypt(self.data!)
        if encrypted == nil {
          XCTAssert(false, "Encryption failed")
        }
        var outData: Encryptable = AppData()
        try? self.sdk?.Decrypt(encrypted!!, dest: &outData)
        
        XCTAssert(self.data! == (outData as! AppData))
        }
  }

}
