//
//  Log.swift
//  Peacemakr-iOS
//
//  Created by Yuliia Synytsia on 5/18/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import Foundation

public class Logger {
  
  /// MARK: - Log levels
  
  /**
   There are several log levels employed by the unified logging system
   
    Default
    Default-level messages are initially stored in memory buffers. Without a configuration change, they are compressed and moved to the data store as memory buffers fill. They remain there until a storage quota is exceeded, at which point, the oldest messages are purged. Use this level to capture information about things that might result a failure.
    Info
    Info-level messages are initially stored in memory buffers. Without a configuration change, they are not moved to the data store and are purged as memory buffers fill. They are, however, captured in the data store when faults and, optionally, errors occur. When info-level messages are added to the data store, they remain there until a storage quota is exceeded, at which point, the oldest messages are purged. Use this level to capture information that may be helpful, but isn’t essential, for troubleshooting errors.
    Debug
    Debug-level messages are only captured in memory when debug logging is enabled through a configuration change. They’re purged in accordance with the configuration’s persistence setting. Messages logged at this level contain information that may be useful during development or while troubleshooting a specific problem. Debug logging is intended for use in a development environment and not in shipping software.
    Error
    Error-level messages are always saved in the data store. They remain there until a storage quota is exceeded, at which point, the oldest messages are purged. Error-level messages are intended for reporting process-level errors. If an activity object exists, logging at this level captures information for the entire process chain.
    Fault
    Fault-level messages are always saved in the data store. They remain there until a storage quota is exceeded, at which point, the oldest messages are purged. Fault-level messages are intended for capturing system-level or multi-process errors only. If an activity object exists, logging at this level captures information for the entire process chain.
 */

  public enum Level: Int {
    /// debug: Use this level to capture information that may be useful during development or while troubleshooting a specific problem.
    case debug = 0
    
    /// info: Use this level to capture information that may be helpful, but isn’t essential, for troubleshooting errors.
    case info = 1
    
    /// default (by the unified logging system): Use this level to capture information about things that might result in a failure.
    /// - important: *Most detailed* log level (includes ifo, warning, error and fault)
    case warning = 2
   
    /// error: Use this log level to capture process-level information to report errors in the process.
    case error = 3
    
    /// fault: Use this level to capture system-level or multi-process information to report system errors.
    case fault = 4
    
    var stringValue: String {
      switch self {
      case .info:
        return "[INFO]"
      case .warning:
        return "[WARNING]"
      case .debug:
        return "[DEBUG]"
      case .error:
        return "[ERROR]"
      case .fault:
        return "[SYSTEM ERROR]"
      }
    }
  }
  
  /// MARK: - Logger
  
  static var consoleOutputs = Set<ConsoleBaseOutput>()
  

  class func setup(_ consoleLogLevel: Level = .debug) {
    consoleOutputs.insert(ConsoleBaseOutput(level: consoleLogLevel))
  }

  
  public class func info(_ message: @autoclosure () -> String, _
    file: String = #file, _ function: String = #function, line: Int = #line) {
    write(level: .info, message: message,
          file: file, function: function, line: line)
  }
  public class func warning(_ message: @autoclosure () -> String, _
    file: String = #file, _ function: String = #function, line: Int = #line) {
    write(level: .warning, message: message,
          file: file, function: function, line: line)
  }
  public class func debug(_ message: @autoclosure () -> String, _
    file: String = #file, _ function: String = #function, line: Int = #line) {
    write(level: .debug, message: message,
          file: file, function: function, line: line)
  }
  public class func error(_ message: @autoclosure () -> String, _
    file: String = #file, _ function: String = #function, line: Int = #line) {
    write(level: .error, message: message,
          file: file, function: function, line: line)
  }
  public class func fault(_ message: @autoclosure () -> String, _
    file: String = #file, _ function: String = #function, line: Int = #line) {
    write(level: .fault, message: message,
          file: file, function: function, line: line)
  }
  public class func onError(_ s: String) -> Void {
    Logger.error(s)
  }
  // internal write to console
  private class func write(level: Logger.Level, message: @autoclosure () -> String,
                           file: String = #file, function: String = #function, line: Int = #line) {
    
    consoleOutputs.forEach {
      $0.log(level: level, message: message(), file: file, function: function, line: line)
    }
  }
  
}
