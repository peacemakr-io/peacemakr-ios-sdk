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

## Setup

1. Get Carthage
2. `cd /path/to/Peacemakr-iOS && carthage update`
3. `open Peacemakr-iOS.xcodeproj`

## Release
The release.sh script takes the destination and output the Peacemakr.framework under that folder.

```
./release.sh /some/dir
```

## Lessons Learned from making this worked
- Runpath search path under "Xcode->Build Setting" indicates the rpath of the built binary. Rpath is a list of paths that dynamic linker look for to get the dependencies/libraries.
- Rpath can also be set using install_name_tools
- MacDependency is a great tool to check what's inside the binary/dylib
- Testing in XCode, BAD_EXEC_ACCESS code=50 can be solved by signing the built binary. Using xcodebuild to test shows better errors.
- Difference between rpath/loader_path/executable_path (https://wincent.com/wiki/%40executable_path%2C_%40load_path_and_%40rpath)
    - executable_path: the application's executable's path.
    - loader_path: plug-in/embedded libraries' path
    - rpath: a list of search path for dynamic linkers
- Required moudle missing "CoreCrypto" Error:
    - What? This happens when we built a Peacemakr.framework and embeded CoreCrypto. The embedded CoreCrypto does not have module.modulemap or any header files included.
    - Fix? add CoreCrypto.frameowkr to Copy Bundle resource.
    - Embededding it or not makes little difference to my knowledge at the moment
- Header issue: crypto.h not found.
    - What? The libCoreCrypto in modulemap is linked to a hard coded path on user's disk. Cannot load in other's computer
    - Fix? Use corecrypto.modulemap to include libCoreCrypto under CoreCrypto framework. (https://medium.com/@yuliiasynytsia/link-static-c-library-to-swift-framework-as-a-private-module-97eae2fec75e)
        - Add corecrypto.modulemap in Build Setting-> Module Map File.
- Building a fat framework. (https://medium.com/@hassanahmedkhan/a-noobs-guide-to-creating-a-fat-library-for-ios-bafe8452b84b)
    - Build iphoneos and iphonesimulator frameworks separately
    - Copy iphoneos over to destination.
    - Copy iphonesimulator's swiftmodule over.
    - Update info.plist
    - Use lipo to combine the iphoneos and iphonesimulator binaries
    - Update rpath/loader_path of binary if needed
    - SIGN THE BINARY
