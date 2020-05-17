#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./release-ios.sh [path to peacemakr-ios folder]"
    echo "for example, ./bin/release-ios.sh ~/peacemakr/peacemakr-ios-sdk"
}

if [[ "$#" -gt 1 ]]; then
    echo "Illegal use"
    usage
    exit 1
fi

if [[ -z "${1}" ]]; then
    echo "Illegal use"
    usage
    exit 1
fi

OUTPUT_DIR=${1}

echo ${OUTPUT_DIR}

PROJECT_SRC=$(pwd)



pushd ${PROJECT_SRC}
pwd
xcodebuild -project Peacemakr-iOS.xcodeproj -scheme Peacemakr-iOS -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 8,OS=13.4.1' test
xcodebuild -project Peacemakr-iOS.xcodeproj BUILD_LIBRARY_FOR_DISTRIBUTION=YES CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO ONLY_ACTIVE_ARCH=NO -configuration Release -miphoneos-version-min=8.1 -sdk iphoneos
xcodebuild -project Peacemakr-iOS.xcodeproj BUILD_LIBRARY_FOR_DISTRIBUTION=YES CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO VALID_ARCHS="x86_64" ONLY_ACTIVE_ARCH=NO -configuration Release -miphoneos-version-min=8.1 -sdk iphonesimulator
popd

mkdir -p ${OUTPUT_DIR}
pushd ${OUTPUT_DIR}
rm -rf Peacemakr.framework || true
cp -R ${PROJECT_SRC}/build/Release-iphoneos/Peacemakr.framework .
cp -R ${PROJECT_SRC}/build/Release-iphonesimulator/Peacemakr.framework/Modules/Peacemakr.swiftmodule/ ${OUTPUT_DIR}/Peacemakr.framework/Modules/Peacemakr.swiftmodule
# defaults write ${OUTPUT_DIR}/Peacemakr.framework/Info.plist CFBundleSupportedPlatforms -array-add "iPhoneSimulator"
plutil -insert CFBundleSupportedPlatforms.1 -string 'iPhoneSimulator'  ${OUTPUT_DIR}/Peacemakr.framework/Info.plist
lipo -create -output "Peacemakr.framework/Peacemakr" "${PROJECT_SRC}/build/Release-iphoneos/Peacemakr.framework/Peacemakr" "${PROJECT_SRC}/build/Release-iphonesimulator/Peacemakr.framework/Peacemakr"
install_name_tool -id "@rpath/Peacemakr.framework/Peacemakr" Peacemakr.framework/Peacemakr
# Important: Link the libpeacemakr-core-crypto.dylib in the framework file.
# There are two options to link: via loader_path or rpath.
#
# loader_path is the path relative to the plug-in aka CoreCrypto here.
# we use loader_path here assuming dylib will always be on the same folder as CoreCrypto binary
#
# rpath tells the dynamic linker to look for the files in a list of folders
# we can also get this working by install_name_tool -add_rpath @loader_path/. CoreCrypto
# install_name_tool -change @rpath/libpeacemakr-core-crypto.dylib @loader_path/libpeacemakr-core-crypto.dylib CoreCrypto.framework/CoreCrypto
/usr/bin/codesign --force --sign - --timestamp=none Peacemakr.framework/Peacemakr
# copy debug info
cp -R ${PROJECT_SRC}/build/Release-iphoneos/Peacemakr.framework.dSYM .
lipo -create -output "Peacemakr.framework.dSYM/Contents/Resources/DWARF/Peacemakr" "${PROJECT_SRC}/build/Release-iphoneos/Peacemakr.framework.dSYM/Contents/Resources/DWARF/Peacemakr" "${PROJECT_SRC}/build/Release-iphonesimulator/Peacemakr.framework.dSYM/Contents/Resources/DWARF/Peacemakr"

# rm -rf ${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build
popd


