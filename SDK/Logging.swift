//
//  Logging.swift
//  Peacemakr-iOS
//
//  Created by Aman LaChapelle on 2/9/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation
import os.log

@available(iOS 10.0, *)
extension OSLog {
  private static let subsystem = "io.peacemakr"
  
  static let network = OSLog(subsystem: subsystem, category: "network")
  static let crypto = OSLog(subsystem: subsystem, category: "crypto")
}

struct PeacemakrError {
  enum SDKSubsystem {
    case Network
    case Crypto
    case Persister
    case RandomDevice
    case Server
    case Swift
  }
  
  var what: String
  var subsystem: SDKSubsystem
  var shouldSend: Bool
  
  var description: String {
    get {
      var outStr = "iOS SDK Subsystem: "
      switch subsystem {
      case .Network:
        outStr += "Network"
      case .Crypto:
        outStr += "Crypto"
      case .Persister:
        outStr += "Persister"
      case .RandomDevice:
        outStr += "RandomDevice"
      case .Server:
        outStr += "API Server"
      case .Swift:
        outStr += "Basic Swift Error"
      }
      
      outStr += " - " + what
      
      return outStr
    }
  }
}

// TODO: log handler that logs to some local system

