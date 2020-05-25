//
//  SDKIntegrationTests.swift
//  Peacemakr-iOS
//
//  Created by Daniel Huang on 4/2/20.
//  Copyright © 2020 Peacemakr. All rights reserved.
//

import XCTest
@testable import Peacemakr

class SDKIntegrationTests: XCTestCase {
  var sdk: Peacemakr? = nil
  var data: AppData? = nil

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
  
  func getAPIKey() -> String{
    SwaggerClientAPI.basePath = "https://api.peacemakr.io/api/v1"
    let gotAPIKey = self.expectation(description: "Got API Key for test org")
  
    var key: String = ""
    OrgAPI.getTestOrganizationAPIKey { (k, err) in
      if err != nil {
        XCTAssert(false, "error")
      }
      
      key = k?.key ?? ""
      print("Test Org API Key: ", key, err)
      gotAPIKey.fulfill()
    }
    
    waitForExpectations(timeout: 5, handler: nil)
    
    return key
  }

  func testRegister() {
    sdk = try? Peacemakr(apiKey: getAPIKey(), url: "https://api.peacemakr.io", testingMode: false)

    XCTAssertNotNil(sdk)

    let expectation = self.expectation(description: "Registration successful")

    sdk?.register(completion: { error in
      XCTAssertNil(error, error!.localizedDescription)
      expectation.fulfill()
    })

    waitForExpectations(timeout: 5, handler: nil)

    XCTAssert(sdk!.registrationSuccessful, "Register failed")
  }

  func testSync() {
    sdk = try? Peacemakr(apiKey: getAPIKey(), url: "https://api.peacemakr.io", testingMode: false)
    XCTAssertNotNil(sdk)

    let expectation = self.expectation(description: "Registration successful")

    sdk?.register(completion: { error in
      XCTAssertNil(error)
      expectation.fulfill()
    })

    waitForExpectations(timeout: 10, handler: nil)

    UserDefaults.standard.synchronize()

    let gotOrgInfoExpectation = self.expectation(description: "Got org info")

    sdk?.sync(completion: { error in
      XCTAssertNil(error)
      gotOrgInfoExpectation.fulfill()
    })

    waitForExpectations(timeout: 60, handler: nil)

  }


  func testEncryptDecrypt() throws {

    sdk = try? Peacemakr(apiKey: "kxfWsPh6EQLmLWOoc9VaZMT5gQvEhK+n55t/gFamwl4=", url: "https://api.peacemakr.io", testingMode: false)
    XCTAssertNotNil(sdk)

    let expectation = self.expectation(description: "Registration successful")

    sdk?.register(completion: { error in
      XCTAssertNil(error)
      expectation.fulfill()
    })

    waitForExpectations(timeout: 10, handler: nil)

    UserDefaults.standard.synchronize()

    let gotOrgInfoExpectation = self.expectation(description: "Got org info")

    sdk?.sync(completion: { error in
      XCTAssertNil(error)
      gotOrgInfoExpectation.fulfill()
    })

    waitForExpectations(timeout: 60, handler: nil)

    XCTAssert(sdk!.registrationSuccessful, "Register failed")

    let decryptExpectation = self.expectation(description: "Decrypt successful")

    let (serialized, err) = sdk!.encrypt(plaintext: data!.serializedValue)
    XCTAssert(err == nil, err!.localizedDescription)
    XCTAssert(serialized != nil, "error: the serialized value is nil")
    
    self.sdk!.decrypt(ciphertext: serialized!, completion: { (dest) in
      XCTAssert(dest.error == nil, dest.error!.localizedDescription)
      XCTAssert(dest.data != nil, dest.error!.localizedDescription)
      XCTAssertEqual(dest.data, self.data?.serializedValue)
      decryptExpectation.fulfill()
    })

    waitForExpectations(timeout: 10, handler: nil)
  }

}
