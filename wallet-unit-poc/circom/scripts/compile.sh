#!/bin/bash

usage() {
  echo "Usage: $0 {jwt|show|ecdsa|all}"
  echo "  jwt: Compile files for JWT."
  echo "  show: Compile files for Show."
  echo "  ecdsa: Compile files for ECDSA."
  echo "  all: Compile all circuits."
  exit 1
}

if [ -z "$1" ]; then
  echo "Error: No option provided."
  usage
fi

case "$1" in
  jwt)
    npx circomkit compile jwt || { echo "Error: Failed to compile JWT."; exit 1; }
    cd build/jwt/ || { echo "Error: 'build/jwt/' directory not found."; exit 1; }
    mv jwt.r1cs jwt_js/ || { echo "Error: Failed to move jwt.r1cs."; exit 1; }
    cd jwt_js || { echo "Error: 'jwt_js' directory not found inside 'build/jwt/'."; exit 1; }
    echo "JWT file processing complete."
    ;;
  show)
    npx circomkit compile show || { echo "Error: Failed to compile Show."; exit 1; }
    cd build/show/ || { echo "Error: 'build/show/' directory not found."; exit 1; }
    mv show.r1cs show_js/ || { echo "Error: Failed to move show.r1cs."; exit 1; }
    cd show_js || { echo "Error: 'show_js' directory not found inside 'build/show/'."; exit 1; }
    echo "Show file processing complete."
    ;;
  ecdsa)
    npx circomkit compile ecdsa || { echo "Error: Failed to compile ECDSA."; exit 1; }
    cd build/ecdsa/ || { echo "Error: 'build/ecdsa/' directory not found."; exit 1; }
    mv ecdsa.r1cs ecdsa_js/ || { echo "Error: Failed to move ecdsa.r1cs."; exit 1; }
    cd ecdsa_js || { echo "Error: 'ecdsa_js' directory not found inside 'build/ecdsa/'."; exit 1; }
    echo "ECDSA file processing complete."
    ;;
  all)
    echo "Compiling all circuits..."
    npx circomkit compile jwt || { echo "Error: Failed to compile JWT."; exit 1; }
    cd build/jwt/ && mv jwt.r1cs jwt_js/ && cd ../.. || { echo "Error: Failed to process JWT."; exit 1; }
    npx circomkit compile show || { echo "Error: Failed to compile Show."; exit 1; }
    cd build/show/ && mv show.r1cs show_js/ && cd ../.. || { echo "Error: Failed to process Show."; exit 1; }
    npx circomkit compile ecdsa || { echo "Error: Failed to compile ECDSA."; exit 1; }
    cd build/ecdsa/ && mv ecdsa.r1cs ecdsa_js/ && cd ../.. || { echo "Error: Failed to process ECDSA."; exit 1; }
    echo "All circuits compiled successfully."
    ;;
  *)
    echo "Error: Invalid option '$1'."
    usage
    ;;
esac

