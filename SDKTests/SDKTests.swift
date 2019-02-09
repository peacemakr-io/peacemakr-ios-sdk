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
  
  let testKey = "1MM/tGB2nztn0YCe185iNq0hnB0+Qnugaxa6ohir79I="
  let gibblygook = "gibblygook"

  override func setUp() {
    super.setUp()
    data = AppData()
    data!.setSomeProperty(prop: "something")
    data!.setSomeOtherProperty(key: "someKey", value: "someValue")
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
  
  func testSync() {
    sdk = PeacemakrSDK(apiKey: testKey, logHandler: log)
    let registerExpectation = self.expectation(description: "Registration Successful")
    XCTAssert(sdk!.Register(completion: {
      XCTAssert($0 == nil)
      registerExpectation.fulfill()
    }), "Initialization of the SDK failed")
    
    waitForExpectations(timeout: 10, handler: nil)
    UserDefaults.standard.synchronize()

    let gotOrgInfoExpectation = self.expectation(description: "Got org info")

    sdk!.Sync(completion: {
      XCTAssert($0 == nil)
      gotOrgInfoExpectation.fulfill()
    })

    waitForExpectations(timeout: 60, handler: nil)

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
    
    let syncExpectation = self.expectation(description: "Sync successful")
    sdk!.Sync { (err) in
      XCTAssert(err == nil)
      syncExpectation.fulfill()
    }

    waitForExpectations(timeout: 30, handler: nil)
    
    XCTAssert(sdk!.RegistrationSuccessful, "Register failed")
    
    let decryptExpectation = self.expectation(description: "Decrypt successful")
    
    let destination = AppData()
    
    let (serialized, err) = sdk!.Encrypt(data!)
    XCTAssert(err == nil)
    
    XCTAssert(self.sdk!.Decrypt(serialized, dest: destination, completion: { (dest) in
      XCTAssert(dest as! AppData == self.data!)
      decryptExpectation.fulfill()
    }))
    
    
    waitForExpectations(timeout: 10, handler: nil)
  }

}
