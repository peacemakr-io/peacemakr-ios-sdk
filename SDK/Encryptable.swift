//
//  Encryptable.swift
//  Peacemakr-iOS
//
//  Created by Aman LaChapelle on 11/4/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import Foundation

/**
 Any object that provides these methods can be encrypted with the Peacemakr SDK.
 Essentially, these just ensure that the object is able to be serialized and
 deserialized. There are two different levels of security associated with Data
 and AAD, please refer to their individual documentation.
 */
public protocol Encryptable {
  /**
   The actual data to be encrypted. This must be serialized into an array of bytes
   for the encryption to work properly, but any serialization scheme is valid as
   long as deserialization is also possible.
   */
  var serializedValue: [UInt8] { get set }
}
