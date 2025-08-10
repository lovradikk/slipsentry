#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
slipsentry — offline slippage sanity-check for DEX calldata.

What it detects (offline):
  • Uniswap V2 swaps: minOut, path[], deadline
  • Uniswap V3 exactInput/exactOutput: path(bytes), amountIn/OutMin/Max, deadline
  • Heuristics & flags: minOut==0, deadline==0 or absurdly large, path len 1, duplicate hops, >5 hops, etc.

Examples:
  $ python slipsentry.py analyze 0x38ed1739... --pretty
  $ python slipsentry.py analyze swaps.txt --json report.json --svg badge.svg
  $ cat data.hex | python slipsentry.py analyze - --pretty
"""

import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple

import click

# ------------------- Known selectors -------------------
# Uniswap V2
SEL_V2_SWAP_EXACT_TOKENS_FOR_TOKENS     = "38ed1739"
SEL_V2_SWAP_TOKENS_FOR_EXACT_TOKENS     = "8803dbee"
SEL_V2_SWAP_EXACT_ETH_FOR_TOKENS        = "7ff36ab5"
SEL_V2_SWAP_EXACT_TOKENS_FOR_ETH        = "18cbafe5"
SEL_V2_SWAP_ETH_FOR_EXACT_TOKENS        = "fb3bdb41"

# Uniswap V3 (Router)
SEL_V3_EXACT_INPUT                       = "04e45aaf"  # exactInput((bytes,address,uint256,uint256,uint256))
SEL_V3_EXACT_OUTPUT                      = "09b81346"  # exactOutput((bytes,address,uint256,uint256,uint256))
# (We focus on these two; single-struct variants are numerous.)

UINT256_MAX = (1 << 256) - 1

# ------------------- Utility -------------------

def strip0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h

def as_bytes(h: str) -> bytes:
    h = strip0x(h).lower()
    if len(h) % 2 != 0:
        raise click.ClickException("Hex length must be even")
    try:
        return bytes.fromhex(h)
    except Exception as e:
        raise click.ClickException(f"Invalid hex: {e}")

def u256(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0

def words(payload: bytes) -> List[bytes]:
    return [payload[i:i+32] for i in range(0, len(payload), 32)]

def is_offset_like(v: int, total: int) -> bool:
    return (v % 32 == 0) and (0 <= v <= max(0, total - 32))

def read_dyn(payload: bytes, off: int) -> Tuple[int, bytes]:
    """Reads [len][bytes] at absolute byte offset 'off' relative to start of payload."""
    if off + 32 > len(payload):
        raise click.ClickException("Dynamic head points out of bounds")
    ln = u256(payload[off:off+32])
    if off + 32 + ln > len(payload):
        raise click.ClickException("Dynamic body truncated")
    return ln, payload[off+32: off+32+ln]

def to_hex_addr(word32: bytes) -> str:
    return "0x" + word32[-20:].hex()

# ------------------- Models -------------------

@dataclass
class Finding:
    level: str     # LOW / MEDIUM / HIGH
    reason: str
    context: Dict[str, Any]

@dataclass
class Report:
    selector: str
    family: str          # v2|v3|unknown
    fn: str              # best name guess
    fields: Dict[str, Any]
    path_tokens: List[str]
    findings: List[Finding]
    risk_score: int
    risk_label: str

# ------------------- Decoders -------------------

def decode_v2(payload: bytes, sel: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    We support common 5-arg V2 swaps:
      swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)
      swapTokensForExactTokens(amountOut, amountInMax, path, to, deadline)
      swapExactETHForTokens(amountOutMin, path, to, deadline)
      swapExactTokensForETH(amountIn, amountOutMin, path, to, deadline)
      swapETHForExactTokens(amountOut, path, to, deadline)
    We parse by positions/offsets; path is a dynamic address[] at arg index 2 (or 1 for ETH variants).
    """
    H = payload  # after selector
    w = words(H)
    total = len(H)
    fields: Dict[str, Any] = {}
    path_tokens: List[str] = []

    def decode_path_at_arg(arg_index: int):
        off = u256(w[arg_index])
        if not is_offset_like(off, total): raise click.ClickException("Bad offset for path[]")
        ln, body = read_dyn(H, off)
        if ln == 0: return []
        if off + 32 + ln*32 > len(H): raise click.ClickException("path[] truncated")
        toks = []
        for i in range(ln):
            toks.append(to_hex_addr(H[off+32 + i*32: off+32 + (i+1)*32]))
        return toks

    if sel in (SEL_V2_SWAP_EXACT_TOKENS_FOR_TOKENS, SEL_V2_SWAP_TOKENS_FOR_EXACT_TOKENS, SEL_V2_SWAP_EXACT_TOKENS_FOR_ETH):
        # amount* are at args 0/1; path is arg 2; to arg 3; deadline arg 4
        fields["amount0"] = u256(w[0])
        fields["amount1"] = u256(w[1])
        path_tokens = decode_path_at_arg(2)
        fields["to"] = to_hex_addr(w[3])
        fields["deadline"] = u256(w[4])
    elif sel in (SEL_V2_SWAP_EXACT_ETH_FOR_TOKENS, SEL_V2_SWAP_ETH_FOR_EXACT_TOKENS):
        # eth variants: (amount*, path, to, deadline)
        fields["amount0"] = u256(w[0])
        path_tokens = decode_path_at_arg(1)
        fields["to"] = to_hex_addr(w[2])
        fields["deadline"] = u256(w[3])
    else:
        raise click.ClickException("Unknown V2 swap layout")

    return fields, path_tokens

def parse_v3_path_bytes(b: bytes) -> List[str]:
    """
    Uniswap V3 path encoding: token(20) [fee(3) token(20)] repeated; ends with token.
    """
    toks: List[str] = []
    i = 0
    if len(b) < 20:
        return toks
    toks.append("0x" + b[i:i+20].hex()); i += 20
    while i < len(b):
        if i + 3 + 20 > len(b): break
        # fee = b[i:i+3]  # unused here
        i += 3
        toks.append("0x" + b[i:i+20].hex())
        i += 20
    return toks

def decode_v3_exact(payload: bytes, sel: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    V3 exactInput / exactOutput have a single tuple argument with:
      (bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum)  [exactInput]
      (bytes path, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum)  [exactOutput]
    We treat the head as 5 words; word0 is offset to path bytes.
    """
    H = payload
    w = words(H)
    total = len(H)
    if len(w) < 5: raise click.ClickException("V3 struct too short")

    path_off = u256(w[0])
    if not is_offset_like(path_off, total): raise click.ClickException("Bad offset for path (V3)")
    ln, path_bytes = read_dyn(H, path_off)

    fields: Dict[str, Any] = {
        "recipient": to_hex_addr(w[1]),
        "deadline": u256(w[2]),
    }
    if sel == SEL_V3_EXACT_INPUT:
        fields["amountIn"] = u256(w[3])
        fields["amountOutMin"] = u256(w[4])
    else:
        fields["amountOut"] = u256(w[3])
        fields["amountInMax"] = u256(w[4])
    path_tokens = parse_v3_path_bytes(path_bytes)
    return fields, path_tokens

# ------------------- Risk heuristics -------------------

def analyze(fields: Dict[str, Any], pa
