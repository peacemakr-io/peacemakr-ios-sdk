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
  var sdk: Peacemakr? = nil
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
    sdk = try? Peacemakr(apiKey: testKey, logLevel: .debug)
    
    XCTAssertNotNil(sdk)
    
    let expectation = self.expectation(description: "Registration successful")
    
    sdk?.register(completion: { error in
      XCTAssertNil(error)
      expectation.fulfill()
    })
    
    waitForExpectations(timeout: 5, handler: nil)
    
    XCTAssert(sdk!.registrationSuccessful, "Register failed")
  }
  
  func testSync() {
    sdk = try? Peacemakr(apiKey: testKey, logLevel: .debug)
    XCTAssertNotNil(sdk)

    sdk?.register(completion: { error in
      XCTAssertNil(error)
    })
    
    UserDefaults.standard.synchronize()

    let gotOrgInfoExpectation = self.expectation(description: "Got org info")
    
    sdk?.sync(completion: { error in
      XCTAssertNil(error)
      gotOrgInfoExpectation.fulfill()
    })

    waitForExpectations(timeout: 60, handler: nil)

  }

  
  func testEncryptDecrypt() throws {
    sdk = try? Peacemakr(apiKey: testKey, logLevel: .debug)
    XCTAssertNotNil(sdk)
    
    sdk?.register(completion: { error in
      XCTAssertNil(error)
    })
    

    let syncExpectation = self.expectation(description: "Sync successful")
    sdk!.sync { (err) in
      XCTAssert(err == nil)
      syncExpectation.fulfill()
    }

    waitForExpectations(timeout: 30, handler: nil)
    
    XCTAssert(sdk!.registrationSuccessful, "Register failed")
    
    let decryptExpectation = self.expectation(description: "Decrypt successful")
    
    let dataToEncrypt = "data to encrypt"
    
    let (serialized, err) = sdk!.encrypt(plaintext: dataToEncrypt)
    XCTAssert(err == nil)
    XCTAssertNotNil(serialized)
    
    sdk!.decrypt(ciphertext: serialized!) { (data, err) in
      if err != nil {
        XCTFail()
      }
      XCTAssert(data == dataToEncrypt)
      decryptExpectation.fulfill()
      
    }
    waitForExpectations(timeout: 10, handler: nil)
  }

}
