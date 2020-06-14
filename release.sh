#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./release-ios.sh [path to release-sdk folder] gh"
    echo "for example, ./release.sh ~/sample-project/Frameworks some-text"
}

if [[ "$#" -gt 2 ]]; then
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
IPHONE_DEST='platform=iOS Simulator,name=iPhone 8,OS=13.5'

pushd ${PROJECT_SRC}
pwd
if [[ -z "${2}" ]]; then
    xcodebuild -project Peacemakr-iOS.xcodeproj -scheme Peacemakr-iOS -sdk iphonesimulator -destination "${IPHONE_DEST}" -only-testing:Peacemakr-iOS-Tests/SDKTests test
fi
xcodebuild -project Peacemakr-iOS.xcodeproj BUILD_LIBRARY_FOR_DISTRIBUTION=YES CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO ONLY_ACTIVE_ARCH=NO -configuration Release -miphoneos-version-min=8.1 -sdk iphoneos
xcodebuild -project Peacemakr-iOS.xcodeproj BUILD_LIBRARY_FOR_DISTRIBUTION=YES CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO VALID_ARCHS="x86_64" ONLY_ACTIVE_ARCH=NO -configuration Release -miphoneos-version-min=8.1 -sdk iphonesimulator
popd

mkdir -p ${OUTPUT_DIR}
pushd ${OUTPUT_DIR}
rm -rf Peacemakr.framework || true
cp -R ${PROJECT_SRC}/build/Release-iphoneos/Peacemakr.framework .
cp -R ${PROJECT_SRC}/build/Release-iphonesimulator/Peacemakr.framework/Modules/Peacemakr.swiftmodule/ ${OUTPUT_DIR}/Peacemakr.framework/Modules/Peacemakr.swiftmodule
defaults write ${OUTPUT_DIR}/Peacemakr.framework/Info.plist CFBundleSupportedPlatforms -array-add "iPhoneSimulator" # plutil -insert CFBundleSupportedPlatforms.1 -string 'iPhoneSimulator'  ${OUTPUT_DIR}/Peacemakr.framework/Info.plist
lipo -create -output "Peacemakr.framework/Peacemakr" "${PROJECT_SRC}/build/Release-iphoneos/Peacemakr.framework/Peacemakr" "${PROJECT_SRC}/build/Release-iphonesimulator/Peacemakr.framework/Peacemakr"
install_name_tool -id "@rpath/Peacemakr.framework/Peacemakr" Peacemakr.framework/Peacemakr

/usr/bin/codesign --force --sign - --timestamp=none Peacemakr.framework/Peacemakr
# copy debug info
cp -R ${PROJECT_SRC}/build/Release-iphoneos/Peacemakr.framework.dSYM .
lipo -create -output "Peacemakr.framework.dSYM/Contents/Resources/DWARF/Peacemakr" "${PROJECT_SRC}/build/Release-iphoneos/Peacemakr.framework.dSYM/Contents/Resources/DWARF/Peacemakr" "${PROJECT_SRC}/build/Release-iphonesimulator/Peacemakr.framework.dSYM/Contents/Resources/DWARF/Peacemakr"

rm -rf ${PROJECT_SRC}/src/ffi/swift/CoreCrypto/build
popd


