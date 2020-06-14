#!/usr/bin/env bash

set -ex


xcodebuild -project Peacemakr-iOS.xcodeproj -scheme Peacemakr-iOS -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 8,OS=13.4.1' -only-testing:Peacemakr-iOS-Tests/SDKTests test
