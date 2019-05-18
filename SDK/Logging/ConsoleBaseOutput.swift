//
//  ConsoleBase.swift
//  Peacemakr-iOS
//
//  Created by Yuliia Synytsia on 5/18/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation

// store operating system / platform
#if os(iOS)
let OS = "iOS"
#elseif os(OSX)
let OS = "OSX"
#elseif os(watchOS)
let OS = "watchOS"
#elseif os(tvOS)
let OS = "tvOS"
#endif

class ConsoleBaseOutput: Hashable, Equatable {
  let product = "Peacemakr"
  
  // each concole base class must have an own hashValue to prevent duplicate outputs
  lazy public var hashValue: Int = 0
  
  // Each output should have a serial queue to prevent writing to the same place of different threads
  var asynchronously = false
  var queue: DispatchQueue?

  
  init(level: Logger.Level = .debug) {
    let queueUUID = NSUUID().uuidString
    let queueLabel = "peacemakr-queue-" + queueUUID
    queue = DispatchQueue(label: queueLabel, qos: .utility, target: queue)
  }
  
  /// MARK: - Formatting
  
  var currentTimestamp: String {
    DateFormatter().dateFormat = "h:mm:ss.sss"
    return DateFormatter().string(from: Date())
  }
  
  func format(level: Logger.Level, message: String, file: String, function: String, line: Int) -> String {
    // NSString has method
    let fileName = NSString(string: file)
    let base = NSString(string: fileName.lastPathComponent)
    
    var consoleMessage = "[\(currentTimestamp):"
    
    switch level {
    case .debug:
      // if level is debug include more info
      consoleMessage = "[\(product)]\(level.stringValue)\(base.deletingPathExtension).\(function):\(line) - \(message)"
    default:
      consoleMessage = "[\(product)]\(level.stringValue) - \(message)"
    }
    
    return consoleMessage
  }
  
  func log(level: Logger.Level, message: String, file: String, function: String, line: Int) {
    guard let queue = queue else { return }
    
    let formatted = format(level: level,
                           message: message,
                           file: file,
                           function: function,
                           line: line)
    if asynchronously {
      queue.async {
        NSLog(formatted)
      }
    } else {
      queue.sync {
        NSLog(formatted)
      }
    }
  }
  
  static func == (lhs: ConsoleBaseOutput, rhs: ConsoleBaseOutput) -> Bool {
    return ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
  }
}
