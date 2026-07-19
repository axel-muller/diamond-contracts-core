#!/usr/bin/env bash

# Pre-requisites:
# - foundry (https://getfoundry.sh)

set -euo pipefail

contracts_path="./contracts/"
abi_path="./abis"

echo "Building..."

if forge build > /dev/null 2>&1 ; then
    echo "Build finished."
else
    echo "Build failed"
    exit 1
fi

rm -rf "${abi_path:?}"/*
mkdir -p "$abi_path"

function iterate_contracts() {
    contracts=("$1"/*.sol)

    for i in "${!contracts[@]}"; do
        [ -f "${contracts[i]}" ] || continue

        contract=$(basename --suffix=.sol "${contracts[i]}")
        echo "[$((i+1))/${#contracts[@]}] Generating ABI for contract $contract"

        forge inspect "${contracts[i]}" abi --json > "$2/${contract}.json"
    done
}

iterate_contracts "$contracts_path" "$abi_path"
