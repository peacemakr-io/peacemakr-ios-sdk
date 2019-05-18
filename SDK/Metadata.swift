//
//  Metadata.swift
//  Peacemakr-iOS
//
//  Created by Yuliia Synytsia on 5/18/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation
import CoreCrypto

class Metadata {
  static let shared = Metadata()
  
  init(){}
  
  var version: String {
    if let bundleInfo = Bundle(for: type(of: self)).infoDictionary,
      let shortVersion = bundleInfo["CFBundleShortVersionString"] as? String,
      let bundleVersion = bundleInfo["CFBundleVersion"] as? String {
      return "\(shortVersion).\(bundleVersion)"
    } else {
      return "<Unknown Peacemakr SDK version>"
    }
  }
  
  var productName: String {
    if let bundleInfo = Bundle(for: type(of: self)).infoDictionary,
      let bundleName = bundleInfo["CFBundleName"] as? String {
      return "\(bundleName)"
    } else {
      return "Peacemakr"
    }
  }
  
}

