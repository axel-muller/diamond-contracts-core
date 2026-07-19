#!/usr/bin/env bash

# Pre-requisites:
# - foundry (https://getfoundry.sh)

set -euo pipefail

contracts_path="./contracts/"
flat_path="${contracts_path}/flat"

echo "Building..."

if forge build > /dev/null 2>&1 ; then
    echo "Build finished."
else
    echo "Build failed"
    exit 1
fi

rm -rf "${flat_path:?}"/*
mkdir -p "$flat_path"

function iterate_contracts() {
    contracts=("$1"/*.sol)

    for i in "${!contracts[@]}"; do
        [ -f "${contracts[i]}" ] || continue

        contract=$(basename --suffix=.sol "${contracts[i]}")
        echo "[$((i+1))/${#contracts[@]}] Flatten contract $contract"

        if ! forge flatten -o "$2/${contract}.sol" "${contracts[i]}" > /dev/null 2>&1 ; then
            echo "flatten of contract $contract failed."
        fi
    done
}

iterate_contracts "$contracts_path" "$flat_path"
