# Contributing to Luva

Thanks for helping improve Luva. This project is **AGPL-3.0-only**; by contributing, you agree your contributions are licensed under the same terms.

## Before you open a PR

1. **Install dev dependencies:** `pip install -e ".[dev]"`
2. **Run checks locally:**
   - `pytest` (or `pytest luva/tests ot_baseline/tests`)
   - `ruff check luva ot_baseline luva.py baseline.py`
   - `mypy luva`
3. **Scope:** Prefer focused changes (one concern per PR). Match existing style and naming.

## Reporting issues

Use [GitHub Issues](https://github.com/cumakurt/luva/issues). Include:

- Luva version or commit hash  
- Python version  
- Minimal command line and, if possible, a **sanitized** PCAP or a public sample path  
- Expected vs actual behavior  

## Security-sensitive findings

Do **not** open public issues for undisclosed vulnerabilities. See [`SECURITY.md`](SECURITY.md) for contact guidance.
