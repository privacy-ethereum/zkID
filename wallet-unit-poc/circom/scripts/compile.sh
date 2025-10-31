#!/bin/bash

usage() {
  echo "Usage: $0 {jwt|ecdsa}"
  echo "  jwt: Compile files for JWT."
  echo "  ecdsa: Compile files for ECDSA."
  exit 1
}

if [ -z "$1" ]; then
  echo "Error: No option provided."
  usage
fi

case "$1" in
  jwt)
    echo "Compiling JWT files..."
    npx circomkit compile jwt || { echo "Error: Failed to compile JWT."; exit 1; }
    cd build/jwt/ || { echo "Error: 'build/jwt/' directory not found."; exit 1; }
    mv jwt.r1cs jwt_js/ || { echo "Error: Failed to move jwt.r1cs."; exit 1; }
    cd jwt_js || { echo "Error: 'jwt_js' directory not found inside 'build/jwt/'."; exit 1; }
    echo "JWT file processing complete."
    ;;
  ecdsa)

    echo "Compiling ECDSA files..."
    npx circomkit compile ecdsa || { echo "Error: Failed to compile ECDSA."; exit 1; }
    cd build/ecdsa/ || { echo "Error: 'build/ecdsa/' directory not found."; exit 1; }
    mv ecdsa.r1cs ecdsa_js/ || { echo "Error: Failed to move ecdsa.r1cs."; exit 1; }
    cd ecdsa_js || { echo "Error: 'ecdsa_js' directory not found inside 'build/ecdsa/'."; exit 1; }
    echo "ECDSA file processing complete."
    ;;
  *)
    echo "Error: Invalid option '$1'."
    usage
    ;;
esac

