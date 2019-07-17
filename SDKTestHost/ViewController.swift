//
//  ViewController.swift
//  SDKTestHost
//
//  Created by Aman LaChapelle on 1/4/19.
//  Copyright © 2019 Peacemakr. All rights reserved.
//

import UIKit
import Peacemakr

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
      let peacemakr = try? Peacemakr(apiKey: "5hB8hRuBkb8J+4SienC5Ix1ZTWL4vhXlve3HLJAxKno=", logLevel: .debug)
//      peacemakr!.register { (error) in
//        if error != nil {
//          NSLog("Registration failed \(error?.localizedDescription)")
//        }
//        peacemakr!.sync(completion: { (error) in
//          if error != nil {
//            NSLog("Failed to sync: \(error)")
//          }
//        })

//      }
      
      
    }
  
//  func ecrypt(_ peacemakr: Peacemakr?) {
//    let (encryptedText, error) = peacemakr!.encrypt(plaintext: "my message")
//    if error != nil {
//      NSLog("Failed to encrypt: \(error)")
//    }
////    peacemakr!.decrypt(ciphertext: encryptedText!, completion: { (data, error) in
////      if error == nil {
////        NSLog("Failed to decrypt")
////      }
////      NSLog("Decrypted message: \(data)")
////    })
//  }


}

