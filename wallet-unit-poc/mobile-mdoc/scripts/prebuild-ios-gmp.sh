#!/bin/bash
set -e

# GMP prebuild for iOS - ensures GMP is built in a clean environment
# This script is idempotent: skips if GMP is already cached

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Cache location
CACHE_DIR="$PROJECT_ROOT/.build-cache"
WITNESSCALC_DIR="$CACHE_DIR/witnesscalc"
GMP_DIR="$WITNESSCALC_DIR/depends/gmp"

# Determine target package based on platform
case "$PLATFORM_NAME" in
    iphonesimulator)
        GMP_TARGET="ios_simulator"
        GMP_PACKAGE="package_iphone_simulator_arm64"
        ;;
    *)
        GMP_TARGET="ios"
        GMP_PACKAGE="package_ios_arm64"
        ;;
esac

GMP_PACKAGE_DIR="$GMP_DIR/$GMP_PACKAGE"

# Check if already built (idempotent)
if [ -d "$GMP_PACKAGE_DIR" ] && [ -f "$GMP_PACKAGE_DIR/lib/libgmp.a" ]; then
    echo "GMP $GMP_TARGET already cached at: $GMP_PACKAGE_DIR"
    exit 0
fi

echo "=================================================="
echo "Building GMP for $GMP_TARGET..."
echo "=================================================="

# Clone witnesscalc if needed
if [ ! -d "$WITNESSCALC_DIR" ]; then
    echo "Cloning witnesscalc repository..."
    mkdir -p "$CACHE_DIR"
    git clone --depth 1 -b secq256r1-support \
        https://github.com/zkmopro/witnesscalc.git "$WITNESSCALC_DIR"
    cd "$WITNESSCALC_DIR"
    # Initialize submodules (nlohmann/json at depends/json)
    git submodule update --init --recursive
    # Fetch secq256r1-support-v2.2.0 branch (needed for v2.2.0 circuits)
    git remote set-branches --add origin secq256r1-support-v2.2.0
    git fetch --depth 1 origin secq256r1-support-v2.2.0
    cd - > /dev/null
fi

# Pre-seed the GMP source archive.
# build_gmp.sh fetches GMP from ftp.gnu.org and nowhere else, and that host is
# frequently unreachable (TLS handshake torn down mid-negotiation). It skips the
# download when the archive is already in place, so fetch it here from a mirror.
GMP_VERSION=6.2.1
GMP_ARCHIVE="gmp-${GMP_VERSION}.tar.xz"
GMP_SHA256=fd4829912cddd12f84181c3451cc752be224643e87fac497b69edddadc49b4f2
GMP_MIRRORS=(
    "https://gmplib.org/download/gmp/${GMP_ARCHIVE}"
    "https://mirrors.kernel.org/gnu/gmp/${GMP_ARCHIVE}"
    "https://ftp.gnu.org/gnu/gmp/${GMP_ARCHIVE}"
)
GMP_ARCHIVE_PATH="$WITNESSCALC_DIR/depends/$GMP_ARCHIVE"

# A truncated archive from an interrupted download is reused as-is by
# build_gmp.sh and only surfaces later as a tar error, so drop it here instead.
if [ -f "$GMP_ARCHIVE_PATH" ] && ! shasum -a 256 -c <<< "$GMP_SHA256  $GMP_ARCHIVE_PATH" > /dev/null 2>&1; then
    echo "Discarding corrupt $GMP_ARCHIVE"
    rm -f "$GMP_ARCHIVE_PATH"
fi

if [ ! -f "$GMP_ARCHIVE_PATH" ]; then
    for GMP_MIRROR in "${GMP_MIRRORS[@]}"; do
        echo "Fetching $GMP_ARCHIVE from $GMP_MIRROR"
        if curl -fsSL --connect-timeout 15 --max-time 300 -o "$GMP_ARCHIVE_PATH.tmp" "$GMP_MIRROR" \
            && shasum -a 256 -c <<< "$GMP_SHA256  $GMP_ARCHIVE_PATH.tmp" > /dev/null 2>&1; then
            mv "$GMP_ARCHIVE_PATH.tmp" "$GMP_ARCHIVE_PATH"
            break
        fi
        rm -f "$GMP_ARCHIVE_PATH.tmp"
        echo "  unavailable, trying next mirror"
    done
fi

if [ ! -f "$GMP_ARCHIVE_PATH" ]; then
    echo "ERROR: could not fetch $GMP_ARCHIVE from any mirror"
    exit 1
fi

cd "$WITNESSCALC_DIR"

# Ensure clean environment for GMP configure
# CRITICAL: Unset variables that cause native compilers to target iOS
unset SDKROOT
unset DEVELOPER_DIR
unset IPHONEOS_DEPLOYMENT_TARGET
unset MACOSX_DEPLOYMENT_TARGET

# CRITICAL: Set CC_FOR_BUILD for cross-compilation
# GMP's configure needs a native macOS compiler to build helper tools that run
# during the build process. Without this, it tries to use the iOS cross-compiler
# (with SDK flags) for native code, which fails.
# Note: build_gmp.sh sets iOS min version via CFLAGS (-mios-simulator-version-min=8.0)
export CC_FOR_BUILD="/usr/bin/clang"
export CPP_FOR_BUILD="/usr/bin/clang -E"

# Build GMP
./build_gmp.sh "$GMP_TARGET"

# Verify
if [ ! -f "$GMP_PACKAGE_DIR/lib/libgmp.a" ]; then
    echo "ERROR: GMP build failed"
    exit 1
fi

echo "=================================================="
echo "GMP prebuild complete: $GMP_PACKAGE_DIR"
echo "=================================================="
