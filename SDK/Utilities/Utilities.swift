//
//  Utilities.swift
//  Peacemakr-iOS
//
//  Created by Yuliia Synytsia on 5/18/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation
import CoreCrypto

class Utilities {
  class func verifyMessage(plaintext: Plaintext, ciphertext: inout Ciphertext, verifyKey: PeacemakrKey, cryptoContext: CryptoContext, completion: (@escaping (Bool) -> Void)) {
    let verified = UnwrapCall(cryptoContext.verify(senderKey: verifyKey, plaintext: plaintext, ciphertext: &ciphertext), onError: Logger.onError)
    if verified == nil || verified == false {
      completion(false)
    }
    completion(true)
  }
}
