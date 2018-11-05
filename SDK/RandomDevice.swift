//
//  RandomDevice.swift
//  SDK
//
//  Created by Aman LaChapelle on 11/4/18.
//  Copyright © 2018 Peacemakr. All rights reserved.
//

import Foundation
import CoreCrypto

/**
 Provides a default random device using the Apple SecRandom* APIs.
 */
public final class PeacemakrRandomDevice: RandomDevice {
    override public init() {
        super.init()
    }
    
    override public var Generator: RNGBuf {
        return { bytes, count in
            return SecRandomCopyBytes(kSecRandomDefault, count, bytes!)
        }
    }
    
    override public var Err: RNGErr {
        return { code in
            switch code {
            case 0:
                return UnsafePointer("OK")
            default:
                return UnsafePointer("unknown error")
            }
        }
    }
}
