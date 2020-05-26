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

  func testRegister() {
    sdk = try? Peacemakr(apiKey: "", url: "http://localhost:8080", testingMode: true)

    XCTAssertNotNil(sdk)

    let expectation = self.expectation(description: "Registration successful")

    sdk?.register(completion: { error in
      XCTAssertNil(error, error!.localizedDescription)
      expectation.fulfill()
    })

    waitForExpectations(timeout: 5, handler: nil)

    XCTAssert(sdk!.registrationSuccessful(), "Register failed")
  }

  func testSync() {
    sdk = try? Peacemakr(apiKey: "", url: "http://localhost:8080", testingMode: true)
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
    sdk = try? Peacemakr(apiKey: "", url: "http://localhost:8080", testingMode: true)
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

    XCTAssert(sdk!.registrationSuccessful(), "Register failed")

    let decryptExpectation = self.expectation(description: "Decrypt successful")

    let (serialized, err) = sdk!.encrypt(plaintext: data!.serializedValue)
    XCTAssert(err == nil, err!.localizedDescription)

    self.sdk!.decrypt(ciphertext: serialized!, completion: { (dest) in
      XCTAssert(dest.error == nil, dest.error!.localizedDescription)
      XCTAssert(dest.data != nil, dest.error!.localizedDescription)
      XCTAssertEqual(dest.data, self.data?.serializedValue)
      decryptExpectation.fulfill()
    })


    waitForExpectations(timeout: 10, handler: nil)
  }

}
