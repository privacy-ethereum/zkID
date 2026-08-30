#!/bin/sh
set -e

BASEDIR=$(dirname "$0")

# Workaround for https://github.com/dart-lang/pub/issues/4010
BASEDIR=$(cd "$BASEDIR" ; pwd -P)

# Remove XCode SDK from path. Otherwise this breaks tool compilation when building iOS project
NEW_PATH=`echo $PATH | tr ":" "\n" | grep -v "Contents/Developer/" | tr "\n" ":"`

export PATH=${NEW_PATH%?} # remove trailing :

# === GMP PREBUILD FOR iOS ===
if [ "$PLATFORM_NAME" = "iphoneos" ] || [ "$PLATFORM_NAME" = "iphonesimulator" ]; then
    # SRCROOT points to flutter/ios/Pods, so go up THREE levels to get project root
    # (PODS_TARGET_SRCROOT points to symlinked path which doesn't work)
    GMP_PROJECT_ROOT="$(cd "$SRCROOT/../../.." && pwd)"
    GMP_PREBUILD_SCRIPT="$GMP_PROJECT_ROOT/scripts/prebuild-ios-gmp.sh"

    if [ -f "$GMP_PREBUILD_SCRIPT" ]; then
        echo "=== GMP Prebuild: Checking cache ==="
        echo "=== Project root: $GMP_PROJECT_ROOT ==="
        # Run prebuild in clean environment to avoid SDKROOT pollution
        env -i \
            HOME="$HOME" \
            PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin" \
            IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}" \
            PLATFORM_NAME="$PLATFORM_NAME" \
            sh "$GMP_PREBUILD_SCRIPT"
    else
        echo "=== GMP Prebuild: Script not found at $GMP_PREBUILD_SCRIPT ==="
    fi

    # Export cache location for build.rs to use (entire witnesscalc directory)
    export WITNESSCALC_PREBUILD_CACHE="$GMP_PROJECT_ROOT/.build-cache/witnesscalc"
fi
# === END GMP PREBUILD ===

env

# Platform name (macosx, iphoneos, iphonesimulator)
export CARGOKIT_DARWIN_PLATFORM_NAME=$PLATFORM_NAME

# Arctive architectures (arm64, armv7, x86_64), space separated.
export CARGOKIT_DARWIN_ARCHS=$ARCHS

# Current build configuration (Debug, Release)
export CARGOKIT_CONFIGURATION=$CONFIGURATION

# Path to directory containing Cargo.toml.
export CARGOKIT_MANIFEST_DIR=$PODS_TARGET_SRCROOT/$1

# Temporary directory for build artifacts.
export CARGOKIT_TARGET_TEMP_DIR=$TARGET_TEMP_DIR

# Output directory for final artifacts.
export CARGOKIT_OUTPUT_DIR=$PODS_CONFIGURATION_BUILD_DIR/$PRODUCT_NAME

# Directory to store built tool artifacts.
export CARGOKIT_TOOL_TEMP_DIR=$TARGET_TEMP_DIR/build_tool

# Directory inside root project. Not necessarily the top level directory of root project.
export CARGOKIT_ROOT_PROJECT_DIR=$SRCROOT

FLUTTER_EXPORT_BUILD_ENVIRONMENT=(
  "$PODS_ROOT/../Flutter/ephemeral/flutter_export_environment.sh" # macOS
  "$PODS_ROOT/../Flutter/flutter_export_environment.sh" # iOS
)

for path in "${FLUTTER_EXPORT_BUILD_ENVIRONMENT[@]}"
do
  if [[ -f "$path" ]]; then
    source "$path"
  fi
done

sh "$BASEDIR/run_build_tool.sh" build-pod "$@"

# Make a symlink from built framework to phony file, which will be used as input to
# build script. This should force rebuild (podspec currently doesn't support alwaysOutOfDate
# attribute on custom build phase)
ln -fs "$OBJROOT/XCBuildData/build.db" "${BUILT_PRODUCTS_DIR}/cargokit_phony"
ln -fs "${BUILT_PRODUCTS_DIR}/${EXECUTABLE_PATH}" "${BUILT_PRODUCTS_DIR}/cargokit_phony_out"
