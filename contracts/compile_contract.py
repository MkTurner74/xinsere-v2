#!/usr/bin/env python3
"""
Compile XinserePermissions.sol and extract bytecode + ABI
"""

from solcx import compile_files, install_solc
import json

# Install solc 0.8.35
print("Installing Solidity 0.8.35...")
install_solc("0.8.35")

# Compile
print("Compiling XinserePermissions.sol...")
compiled = compile_files(
    ["XinserePermissions.sol"],
    output_values=["bin", "abi"],
    solc_version="0.8.35"
)

# Extract bytecode and ABI
contract_name = "XinserePermissions.sol:XinserePermissions"
if contract_name in compiled:
    contract = compiled[contract_name]
    bytecode = contract['bin']
    abi = contract['abi']

    print(f"\n[OK] Compilation successful\n")
    print(f"Bytecode length: {len(bytecode)} characters")
    print(f"First 100 chars: 0x{bytecode[:100]}...")
    print(f"\nABI: {len(abi)} functions/events")

    # Save bytecode
    with open("bytecode.txt", "w") as f:
        f.write("0x" + bytecode)
    print("\n[OK] Saved: bytecode.txt")

    # Save ABI
    with open("abi.json", "w") as f:
        json.dump(abi, f, indent=2)
    print("[OK] Saved: abi.json")

    # Print for copy-paste
    print("\n" + "="*70)
    print("BYTECODE (for deploy script):")
    print("="*70)
    print(f"contract_bytecode = '0x{bytecode}'")
    print("="*70)

else:
    print(f"✗ Contract not found. Available: {list(compiled.keys())}")
