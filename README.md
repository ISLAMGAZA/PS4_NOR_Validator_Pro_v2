# PS4 NOR Validator Pro v2

> **Early Development** — This project is in its early stages. Features are being actively developed and tested. Use at your own risk.

Advanced PS4 NOR dump analysis, validation, repair, and downgrade tool.

## Features

- **Hybrid Auto-Repair v2.1** — 4-pass repair pipeline (FW Blob, Same-FW Donor, Cross-Donor Cascade, Byte-Level with identity protection)
- **HDD/NVS Analyzer** — 9 sub-region analysis with CB (0xFF) health check
- **Syscon Regeneration** — WeeTools rebuild, donor-based, from-scratch SNVS generation
- **Syscon Damage Analysis** — 4 severity levels with graduated auto-repair
- **Downgrade Assistant** — CORE_SWCH slot flip, UART enable, EAP_KBL replacement, Syscon SNVS patch (Method A/B)
- **NVS Regeneration** — 3 methods (Accurate Bytes, Blind Copy, Combined) with Board ID filtering
- **Smart Donor Matching** — Weighted scoring by series, model, region, and FW version
- **ARV-to-FW Mapping** — 207 entries built from 380 paired dumps
- **Keys Extractor** — Console identity and encryption keys
- **SLB2 Rebuilder** — Secure boot partition repair

## Quick Start

```
# Interactive menu
main_v2.py

# CLI mode
main_v2.py <dump.bin> [command]
```

### Menu Overview

| Key | Feature |
|-----|---------|
| L | Load NOR dump |
| R | Smart Auto-Repair v2 |
| E | Hybrid Auto-Repair v2.1 |
| H | HDD Metadata Analyzer |
| D | Analyze Damage |
| G | Guided Interactive Repair |
| N | NVS Regeneration (3 methods) |
| C | Syscon Regeneration |
| V | Downgrade Assistant |
| S | Smart Donor Match |
| 4 | Extract Console Keys |
| 5 | Extract HDD XTS Keys |

## Requirements

- Python 3.9+
- Donor NOR dumps (see `donors/`)
- Syscon donor dumps (see `syscon_donors/`)
- FW blob database (see `fws/`)

## License

GPL-3.0 — Open source. Contributions welcome.

## Notes

- Always keep backups of your original NOR dump
- Console identity (Board ID, MAC, Serial, CID) is preserved during repair
- This is a community tool with no affiliation to Sony Interactive Entertainment
- Currently under active development — expect changes and improvements
