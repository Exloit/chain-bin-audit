#!/usr/bin/env python3
"""
Address candidate extractor for blockchain binary audit.
Reference template — AI adapts regex patterns based on the user's target chains.
Usage: python3 -I detect_addresses.py [--chains ETH,BTC,...] <file1> [file2 ...]
Output: JSON array of candidate addresses to stdout
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

CHAIN_PATTERNS = {
    "ETH": {
        "regex": r"0x[0-9a-fA-F]{40}",
        "description": "Ethereum address (0x + 40 hex chars)",
    },
    "BTC_LEGACY": {
        "regex": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
        "description": "Bitcoin legacy address (P2PKH/P2SH)",
    },
    "BTC_BECH32": {
        "regex": r"bc1[a-zA-HJ-NP-Za-km-z0-9]{25,90}",
        "description": "Bitcoin bech32 address",
    },
    "SOLANA": {
        "regex": r"[1-9A-HJ-NP-Za-km-z]{32,44}",
        "description": "Solana address (base58, 32-44 chars)",
    },
    "TRON": {
        "regex": r"T[a-zA-HJ-NP-Za-km-z1-9]{33}",
        "description": "Tron address (T + 33 base58 chars)",
    },
    "COSMOS": {
        "regex": r"cosmos1[a-z0-9]{38}",
        "description": "Cosmos bech32 address",
    },
}


def extract_strings(file_path: str, min_length: int = 20) -> list[tuple[str, int]]:
    try:
        result = subprocess.run(
            ["strings", "-t", "x", f"-n{min_length}", file_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        entries = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                offset_str, content = parts
                try:
                    offset = int(offset_str, 16)
                except ValueError:
                    offset = -1
                entries.append((content, offset))
        return entries
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def scan_file(file_path: str, chains: list[str]) -> list[dict]:
    candidates = []
    seen = set()

    patterns = {}
    for chain in chains:
        chain_upper = chain.upper().strip()
        if chain_upper == "BTC":
            patterns["BTC_LEGACY"] = CHAIN_PATTERNS["BTC_LEGACY"]
            patterns["BTC_BECH32"] = CHAIN_PATTERNS["BTC_BECH32"]
        elif chain_upper in CHAIN_PATTERNS:
            patterns[chain_upper] = CHAIN_PATTERNS[chain_upper]

    if not patterns:
        patterns = CHAIN_PATTERNS

    strings_data = extract_strings(file_path)
    if not strings_data:
        return []

    for content, offset in strings_data:
        for chain_name, chain_info in patterns.items():
            for match in re.finditer(chain_info["regex"], content):
                addr = match.group(0)
                dedup_key = f"{addr}:{file_path}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                context_start = max(0, match.start() - 20)
                context_end = min(len(content), match.end() + 20)
                context = content[context_start:context_end]

                candidates.append({
                    "address": addr,
                    "chain_hint": chain_name.replace("_LEGACY", "").replace("_BECH32", ""),
                    "file": file_path,
                    "offset_hex": f"0x{offset:x}" if offset >= 0 else "unknown",
                    "context": context,
                })

    return candidates


def main():
    parser = argparse.ArgumentParser(
        description="Extract blockchain address candidates from binary files"
    )
    parser.add_argument("files", nargs="+", help="Binary file paths to scan")
    parser.add_argument(
        "--chains",
        default="ETH,BTC,SOLANA,TRON,COSMOS",
        help="Comma-separated chain list (default: ETH,BTC,SOLANA,TRON,COSMOS)",
    )
    args = parser.parse_args()

    chains = [c.strip() for c in args.chains.split(",")]
    all_candidates = []

    for file_path in args.files:
        if not Path(file_path).is_file():
            print(f"Warning: {file_path} not found, skipping", file=sys.stderr)
            continue
        all_candidates.extend(scan_file(file_path, chains))

    print(json.dumps(all_candidates, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
