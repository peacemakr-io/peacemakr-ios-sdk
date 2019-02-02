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
  
  let testKey = "Ie/LmqLI3yJm7yASKd4jnoYJvYwLs9m5t7Fr/mNtb6I="
  let gibblygook = "gibblygook"

  override func setUp() {
    super.setUp()
    data = AppData()
    data?.setSomeProperty(prop: "something")
    data?.setSomeOtherProperty(key: "someKey", value: "someValue")
  }

  override func tearDown() {
    super.tearDown()
    // Put teardown code here. This method is called after the invocation of each test method in the class.
  }
  
  func testRegister() {
    sdk = PeacemakrSDK(apiKey: testKey, logHandler: log)
    
    let expectation = self.expectation(description: "Registration successful")
    
    if !sdk!.Register(completion: {
      XCTAssert($0 == nil)
      expectation.fulfill()
    }) {
      XCTAssert(false, "Initialization of the SDK failed")
    }

    waitForExpectations(timeout: 5, handler: nil)
    
    XCTAssert(sdk!.RegistrationSuccessful, "Register failed")
  }

  func testEncryptDecrypt() throws {
    sdk = PeacemakrSDK(apiKey: testKey, logHandler: log)
    
    let registerExpectation = self.expectation(description: "Registration successful")
    
    if !sdk!.Register(completion: {
      XCTAssert($0 == nil)
      registerExpectation.fulfill()
    }) {
      XCTAssert(false, "Initialization of the SDK failed")
    }
    
    waitForExpectations(timeout: 5, handler: nil)
    
    XCTAssert(sdk!.RegistrationSuccessful, "Register failed")
    
    let encryptExpectation = self.expectation(description: "Encrypt successful")
    let decryptExpectation = self.expectation(description: "Decrypt successful")
    
    let destination = AppData()
    
    let decryptCall = { (serialized) in
      self.sdk!.Decrypt(serialized, dest: destination, completion: { (dest) in
        XCTAssert(dest as! AppData == self.data!)
        decryptExpectation.fulfill()
      })
    }
    
    sdk!.Encrypt(data!, completion: { (serialized, err) in
      XCTAssert(err == nil)
      encryptExpectation.fulfill()
      
      XCTAssert(decryptCall(serialized))
    })
    
    waitForExpectations(timeout: 10, handler: nil)
  }

}
