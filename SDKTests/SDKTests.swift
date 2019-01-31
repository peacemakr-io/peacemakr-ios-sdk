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
  
  let testKey = "peacemaker-key-123-123-123"
  let gibblygook = "gibblygook"

  override func setUp() {
    sdk = PeacemakrSDK(apiKey: testKey, logHandler: log)
    if !sdk!.Register() {
      XCTAssert(false, "Initialization of the SDK failed")
    }
    
    var i = 0
    while !sdk!.RegistrationSuccessful && i < 100 {
      sleep(1)
      i+=1
    }
    
    if !sdk!.RegistrationSuccessful {
      XCTAssert(false, "Register failed!")
    }
    
    data = AppData()
    data?.setSomeProperty(prop: "something")
    data?.setSomeOtherProperty(key: "someKey", value: "someValue")
  }

  override func tearDown() {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
  }

  func testEncryptDecrypt() throws {
    XCTAssert(sdk!.RegistrationSuccessful)
    let encrypted = sdk?.Encrypt(data!)
    if encrypted == nil {
      XCTAssert(false, "Encryption failed")
    }
    var outData: Encryptable = AppData()
    sdk?.Decrypt(encrypted!, dest: &outData)
    
    XCTAssert(data! == (outData as! AppData))
  }

  func testPerformanceExample() {
      self.measure {
        let encrypted = self.sdk?.Encrypt(self.data!)
        if encrypted == nil {
          XCTAssert(false, "Encryption failed")
        }
        var outData: Encryptable = AppData()
        self.sdk?.Decrypt(encrypted!, dest: &outData)
        
        XCTAssert(self.data! == (outData as! AppData))
        }
  }

}
