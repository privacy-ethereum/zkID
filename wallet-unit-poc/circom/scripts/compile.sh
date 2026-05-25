#!/bin/bash

usage() {
    echo "Usage: $0 {certChainRS2048|certChainRS4096|userSigRS2048|all|copy}"
    echo "  certChainRS2048: Phase 2 split — Circuit A (cert chain + revocation) for MOICA-G2."
    echo "  certChainRS4096: Phase 2 split — Circuit A for MOICA-G3 (4096-bit issuer, 2048-bit user)."
    echo "  userSigRS2048: Phase 2 split — Circuit B (device signature); always RSA-2048 (user keys are always 2048-bit)."
    echo "  all:               Compile all circuits."
    echo "  copy:              Copy compiled cpp/dat files to ecdsa-spartan2/circuits/."
    exit 1
}

if [ -z "$1" ]; then
    echo "Error: No option provided."
    usage
fi

function compile() {
    circuit_name=$1
    npx circomkit compile $circuit_name || { echo "Error: Failed to compile $circuit_name."; exit 1; }
    cd build/$circuit_name/ || { echo "Error: 'build/$circuit_name/' directory not found."; exit 1; }
    mv $circuit_name.r1cs ${circuit_name}_js/ || { echo "Error: Failed to move $circuit_name.r1cs."; exit 1; }
    cd ../.. || exit 1
    mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
    cp -f build/$circuit_name/${circuit_name}_cpp/$circuit_name.cpp build/cpp/
    cp -f build/$circuit_name/${circuit_name}_cpp/$circuit_name.dat build/cpp/
    echo "$circuit_name circuit compiled successfully."
}


case "$1" in
    certChainRS2048)
        compile certChainRS2048
    ;;
    certChainRS4096)
        compile certChainRS4096
    ;;
    userSigRS2048)
        compile userSigRS2048
    ;;
    all)
        compile certChainRS2048
        compile certChainRS4096
        compile userSigRS2048
    ;;
    copy)
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        CIRCUITS_DIR="$SCRIPT_DIR/../../ecdsa-spartan2/circuits"
        mkdir -p "$CIRCUITS_DIR"
        for f in certChainRS2048 certChainRS4096 userSigRS2048; do
            for ext in cpp dat; do
                src="$SCRIPT_DIR/../build/cpp/${f}.${ext}"
                if [ -f "$src" ]; then
                    cp -f "$src" "$CIRCUITS_DIR/"
                    echo "Copied ${f}.${ext} → ecdsa-spartan2/circuits/"
                else
                    echo "Warning: $src not found, skipping"
                fi
            done
        done
    ;;
    *)
        echo "Error: Invalid option '$1'."
        usage
    ;;
esac
