# Peacemakr iOS SDK

This repository contains the Swift implementation of the peacemakr SDK.

In order to build the core crypto lib for this repo, execute the following command:
```
cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /path/to/peacemakr-sdk-ios
```

After this you should be able to open your peacemakr-sdk-ios Xcode project and develop normally.

You may run into mysterious 400 and 404 errors, if you do, check the request code is escaping things properly. The generated swift should have something like this
```
let apikeyPostEscape = apikeyPreEscape.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? ""
```
