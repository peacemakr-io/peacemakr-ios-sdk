//
//  Constants.swift
//  Peacemakr-iOS
//
//  Created by Yuliia Synytsia on 5/18/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation

struct Constants {
  /// MARK: - Constants
  
  static let dataPrefix = "io.peacemakr.client."
  static let privTag = "io.peacemakr.client.private"
  static let pubTag = "io.peacemakr.client.public"
  // symmetric keys start with this prefix and append the key ID onto it
  static let symmTagPrefix = "io.peacemakr.client.symmetric."
  static let clientIDTag = "ClientID"
  static let pubKeyIDTag = "PubKeyID"
  static let clientKeyTTL = "ClientKeyTTL"
  static let keyCreationTime = "KeyCreationTime"
  static let clientKeyType = "KeyType"
  static let clientKeyLen = "KeyBitlen"
  static let orgID = "OrgID"
  static let cryptoConfigID = "CryptoConfigID"
  static let udSelectorScheme = "UseDomainSelectorScheme"
  static let useDomains = "UseDomains"
  
  static let Chacha20Poly1305 = "Peacemakr.Symmetric.CHACHA20_POLY1305"
  static let Aes128gcm        = "Peacemakr.Symmetric.AES_128_GCM"
  static let Aes192gcm        = "Peacemakr.Symmetric.AES_192_GCM"
  static let Aes256gcm        = "Peacemakr.Symmetric.AES_256_GCM"
  
  static let Sha224 = "Peacemakr.Digest.SHA_224"
  static let Sha256 = "Peacemakr.Digest.SHA_256"
  static let Sha384 = "Peacemakr.Digest.SHA_384"
  static let Sha512 = "Peacemakr.Digest.SHA_512"
}
