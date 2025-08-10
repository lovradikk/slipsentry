# slipsentry — offline slippage sanity-check for DEX calldata

**slipsentry** inspects raw Ethereum **swap calldata** and warns you about
dangerous slippage & deadline settings — without RPC, ABIs, or a signatures DB.

It currently understands:
- **Uniswap V2** `swap*` calls (selector-based, no ABI needed)
- **Uniswap V3** `exactInput` / `exactOutput` (parses the `path` bytes)

## Why this is useful

Ruggy sites and scripts sometimes sneak in:
- `amountOutMin == 0` (accept **any** price)
- `deadline == 0` (never expires) or absurdly far deadlines
- odd `path` shapes (single-token no-op, duplicate hops, too many hops)

**slipsentry** catches those from the `0x…` blob alone so reviewers can stop a bad
swap *before* signing.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
