<p align="center">
  <br>
    <img src="https://admin.peacemakr.io/p_logo.png" width="150"/>
  <br>
</p>

# Peacemakr E2E-Encryption-as-a-Service iOS SDK

Peacemakr's E2E-Encryption-as-a-Service SDK simplify your data security with E2E-Encryption service and automated key lifecycle management.

You can easily encrypt your data without worrying about backward compatibility, cross platform portability, or changing security requirements.

Our Zero-Trust capability allows you to customize your security strength to meet the highest standard without having to place your trust in Peacemakr as we don’t have the capacity to get your keys and decrypt your data.

## License

The content of this SDK is open source under [Apache License 2.0](https://github.com/peacemakr-io/peacemakr-python-sdk/blob/master/LICENSE).

## Setup

1. Get Carthage
2. `cd /path/to/Peacemakr-iOS && carthage update`
3. `open Peacemakr-iOS.xcodeproj`

## Release
The release.sh script takes the destination and output the Peacemakr.framework under that folder.

```
./release.sh /some/dir
```

## Building / Project Structure
/peacemakr-ios-sdk
    /Frameworks
        CoreCrypto
        Alamofire
    Peacemakr-iOS.xcodproj

## Testing
Make sure the Signing & Certificate is set to your development/personal account if you are testing on a real iphone.

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
- Testing on real iphone
    - Two ways to make it work with the signing requirements
        1. Embed & Sign everything
        2. Add a build phase with the script in https://github.com/Carthage/Carthage/issues/1401
        ```
        for f in $(find $CODESIGNING_FOLDER_PATH -name '*.framework')
        do
            codesign --force --sign "${CODE_SIGN_IDENTITY}" --preserve-metadata=identifier,entitlements --timestamp=none "$f"
        done

        for f in $(find $CODESIGNING_FOLDER_PATH -name 'libpeacemakr-core-crypto.dylib')
        do
            codesign --force --sign "${CODE_SIGN_IDENTITY}" --preserve-metadata=identifier,entitlements --timestamp=none "$f"
        done
        ```
        - Remember to sign the dylib too :)

## FAQ

In order to build the core crypto lib for this repo, execute the following command:
```
cd /path/to/peacemakr-core-crypto/bin && ./release-ios.sh /path/to/peacemakr-sdk-ios
```

After this you should be able to open your peacemakr-sdk-ios Xcode project and develop normally.

You may run into mysterious 400 and 404 errors, if you do, check the request code is escaping things properly. The generated swift should have something like this
```
let apikeyPostEscape = apikeyPreEscape.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? ""
```
