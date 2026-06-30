#!/usr/bin/env python3
"""
PS4 NOR Validator Pro v2 — Syscon FW DB + Keys Extractor + SLB2 + Smart Donor
Advanced features interactive menu.
"""

import os
import sys
import time
from typing import Optional

# Ensure project root is in path (works with PyInstaller)
if getattr(sys, 'frozen', False):
    ROOT = os.path.dirname(sys.executable)
else:
    ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ps4nor.v2_features import (
    __version__,
    SYSCON_FW_MD5, EFUSE_MIN_FW, SYSCON_CHIPS,
    detect_syscon_fw, check_efuse_downgrade_safety,
    read_efuse_bits, format_syscon_report,
    ConsoleKeysExtractor, extract_console_keys,
    SLB2Rebuilder, rebuild_slb2, parse_slb2,
    SmartDonorMatcher, find_best_donor, get_donor_suggestions,
    DonorInfo, MatchResult,
    analyze_hdd_metadata, repair_hdd_metadata, format_hdd_report,
    HDD_KEY_MAGIC, HDD_KEY_BLOB, HDD_KEY_BACKUP_MAGIC, HDD_KEY_BACKUP_BLOB,
    HybridRepairV21,
)
from ps4nor.v2_features.donor_repair_integration import (
    SmartAutoRepair, smart_auto_repair, CRITICAL_REGIONS, REGION_MIN_HEALTHY, SHARABLE_SECTIONS,
)
from ps4nor.utils.helpers import detect_sku, detect_fw_version
from ps4nor.utils.colors import C, ok, fail, warn, info, title, brand, dim, value, hr, head, data

DUMPS_DIR = os.path.join(ROOT, 'dumps')
DONORS_DIR = os.path.join(ROOT, 'donors')
FWS_DIR = os.path.join(ROOT, 'fws')
DATA_DIR = os.path.join(ROOT, 'data')
REVERT_DIR = os.path.join(ROOT, 'revert')
SYSCON_DONORS_DIR = os.path.join(ROOT, 'syscon_donors')

os.makedirs(DUMPS_DIR, exist_ok=True)
os.makedirs(DONORS_DIR, exist_ok=True)
os.makedirs(FWS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REVERT_DIR, exist_ok=True)
os.makedirs(SYSCON_DONORS_DIR, exist_ok=True)

# ---- Globals ----
_current_dump: Optional[bytes] = None
_current_path: Optional[str] = None


# ======================================================================
# HELPERS
# ======================================================================

def _header(t: str):
    print()
    print(hr(color='cyan'))
    print(f'  {title(t)}')
    print(hr(color='cyan'))


def _load_dump(path: str = None) -> bool:
    global _current_dump, _current_path
    if path:
        _current_path = path
    elif not _current_path:
        dumps = [f for f in os.listdir(DUMPS_DIR) if f.endswith(('.bin', '.BIN', '.nor', '.NOR'))]
        if not dumps:
            print('No dumps in dumps/. Place a NOR dump first.')
            return False
        print('Available dumps:')
        for i, f in enumerate(dumps, 1):
            size = os.path.getsize(os.path.join(DUMPS_DIR, f))
            print(f'  {ok(f"[{i}]")} {head(f)}  {dim(f"({size:,} bytes)")}')
        try:
            idx = int(input('Select dump: ')) - 1
            _current_path = os.path.join(DUMPS_DIR, dumps[idx])
        except (ValueError, IndexError):
            print('Invalid selection.')
            return False

    try:
        with open(_current_path, 'rb') as f:
            _current_dump = f.read()
        print(f'Loaded: {os.path.basename(_current_path)} ({len(_current_dump):,} bytes)')
        return True
    except Exception as e:
        print(f'Error loading dump: {e}')
        return False


def _load_syscon() -> Optional[bytes]:
    """Extract Syscon (512KB from 0x60000) from current dump."""
    if not _current_dump or len(_current_dump) < 0xE0000:
        print('No valid NOR dump loaded.')
        return None
    if len(_current_dump) >= 0x60000 + 0x80000:
        return _current_dump[0x60000:0x60000 + 0x80000]
    return _current_dump[-0x80000:] if len(_current_dump) >= 0x80000 else None


def _pause():
    input('\nPress Enter to continue...')


def browse_file(desc, directory):
    """Let user browse and select a .bin file from a directory."""
    if not os.path.isdir(directory):
        print(f'  {warn(f"Directory not found: {directory}")}')
        path = input(f'  {info(f"Enter {desc} path:")} ').strip()
        return path if os.path.isfile(path) else ''

    files = sorted([f for f in os.listdir(directory) if f.upper().endswith('.BIN')])
    if not files:
        print(f'  {warn("No .bin files found.")}')
        path = input(f'  {info(f"Enter {desc} path:")} ').strip()
        return path if os.path.isfile(path) else ''

    print(f'  {info("Files in")} {value(directory)}')
    for i, f in enumerate(files, 1):
        sz = os.path.getsize(os.path.join(directory, f))
        print(f'    {ok(f"[{i}]")} {head(f)}  {dim(f"({sz:,} bytes)")}')
    print(f'    {ok("[M]")} {dim("Manual path entry")}')

    sel = input(f'  {info("Select file")} (1-{len(files)}): ').strip().lower()
    if sel == 'm':
        path = input(f'  {info(f"Enter {desc} path:")} ').strip()
        return path if os.path.isfile(path) else ''
    try:
        idx = int(sel) - 1
        return os.path.join(directory, files[idx])
    except (ValueError, IndexError):
        return ''


def _get_dump_path() -> Optional[str]:
    if _current_path:
        return _current_path
    print('No dump loaded.')
    return None


# ======================================================================
# FEATURE: SYSCON FW DATABASE
# ======================================================================

def syscon_analysis():
    _header('SYSCON FIRMWARE ANALYSIS')
    syscon = _load_syscon()
    if not syscon:
        print('Cannot extract Syscon from dump.')
        return

    report = format_syscon_report(syscon)
    print(report)

    # Extra: efuse downgrade check
    print('\n  --- Downgrade Safety Check ---')
    sku = input('  Enter model prefix (e.g. CUH-22, CUH-72): ').strip().upper()
    target = input('  Enter target FW (e.g. 9.00): ').strip()
    if sku and target:
        safety = check_efuse_downgrade_safety(syscon, target, sku)
        print(f'  Safe: {safety["safe"]}')
        for w in safety['warnings']:
            print(f'  WARNING: {w}')


def syscon_efuse_bits():
    _header('SYSCON EFUSE BITS')
    syscon = _load_syscon()
    if not syscon:
        return
    efuse = read_efuse_bits(syscon)
    arv = efuse['anti_rollback_version']; mrf = efuse['model_region_flags']
    sbf = efuse['secure_boot_flags']; kn = efuse['kannyu']
    print(f'  {info("Anti-rollback:")}   {value(f"0x{arv:04x}")}')
    print(f'  {info("Model/Region:")}    {value(f"0x{mrf:04x}")}')
    print(f'  {info("Secure boot:")}     {value(f"0x{sbf:04x}")}')
    print(f'  {info("Kannyu (Mfg):")}    {value(f"0x{kn:04x}")}')
    print(f'  {info("PRE entries:")}     {len(efuse["raw_entries"])}')
    for e in efuse['raw_entries']:
        et = e['type']; ec = e['counter']
        print(f'    {info(et)} @ {e["offset"]}: {dim(f"cnt={ec}")} {value(e["data"])}')


def syscon_database_stats():
    _header('SYSCON FW DATABASE STATS')
    print(f'  Total MD5 entries:  {len(SYSCON_FW_MD5)}')
    print(f'  Total eFuse models: {len(EFUSE_MIN_FW)}')
    print(f'  Syscon chips:       {len(SYSCON_CHIPS)}')
    print()
    for chip, info in SYSCON_CHIPS.items():
        print(f'  {chip}:')
        print(f'    Models: {", ".join(info["models"])}')
        print(f'    Arch:   {info["arch"]}')
        print(f'    Flash:  {info["flash_size"]:#x}')
    print()
    # FW version list
    print('  Firmware versions by model:')
    for model in sorted(set(v['models'][0] for v in SYSCON_FW_MD5.values())):
        vers = set()
        for v in SYSCON_FW_MD5.values():
            if model in v['models']:
                vers.add(v['version'])
        print(f'    {model}: {", ".join(sorted(vers, key=lambda x: tuple(map(int, x.split(".")))))}')


# ======================================================================
# FEATURE: KEYS EXTRACTOR
# ======================================================================

def extract_all_keys():
    _header('CONSOLE KEYS EXTRACTION')
    if not _load_dump():
        return

    syscon = _load_syscon()
    extractor = ConsoleKeysExtractor(_current_dump, syscon)
    keys = extractor.extract_all()
    print(extractor.to_text_report())


def extract_hdd_keys():
    _header('HDD XTS KEY EXTRACTION')
    if not _load_dump():
        return

    syscon = _load_syscon()
    extractor = ConsoleKeysExtractor(_current_dump, syscon)
    hdd = extractor._extract_hdd_keys()
    print(f'  {info("Blob offset:")} {value(hdd.get("blob_offset", "N/A"))}')
    print(f'  {info("Valid:")}       {ok("True") if hdd.get("valid") else fail("False")}')
    if hdd.get('valid'):
        print(f'  {title("Data Key:")}    {value(hdd["data_key_hex"])}')
        print(f'  {title("Tweak Key:")}   {value(hdd["tweak_key_hex"])}')
        print(f'  {info("SMI:")}         {dim(hdd.get("smi", "N/A"))}')
        hmac_ok = hdd.get('hmac_verified')
        if hmac_ok is True:
            print(f'  {info("HMAC:")}        {ok("VERIFIED")}')
        elif hmac_ok is False:
            print(f'  {info("HMAC:")}        {warn("MISMATCH")}')
        else:
            print(f'  {info("HMAC:")}        {dim("N/A")}')
    else:
        print(f'  {fail("Error:")}       {warn(hdd.get("error", "Unknown"))}')


def extract_vtrm_keys():
    _header('VTRM KEYS (eFuse PRE0-PRE3)')
    syscon = _load_syscon()
    if not syscon:
        return
    extractor = ConsoleKeysExtractor(b'', syscon)
    vtrm = extractor._extract_vtrm_keys()
    print(f'  {info("Total entries:")} {vtrm["count"]}')
    for t, e in vtrm.get('latest_entries', {}).items():
        c = e['counter']
        print(f'  {info(t)} {dim(f"(ctr={c})")}: {value(e["data_hex"])}')


def extract_ssc_keys():
    _header('SSC/SSK KEYS (MODE0-BOOT3)')
    syscon = _load_syscon()
    if not syscon:
        return
    extractor = ConsoleKeysExtractor(b'', syscon)
    ssc = extractor._extract_ssc_ssk()
    print(f'  {info("Total entries:")} {ssc["count"]}')
    for t, e in ssc.get('latest_entries', {}).items():
        c = e['counter']
        print(f'  {info(t)} {dim(f"(ctr={c})")}: {value(e["data_hex"])}')


# ======================================================================
# FEATURE: SLB2 REBUILDER
# ======================================================================

def slb2_rebuild():
    _header('SLB2 PARTITION REBUILDER')
    print('  1. Parse existing SLB2 from dump')
    print('  2. Build new SLB2 from scratch')
    print('  3. View parsed SLB2 report')
    choice = input('Select: ').strip()

    if choice == '1':
        if not _load_dump():
            return
        print('  Scanning for SLB2 partitions...')
        for name, offset in [('EMC_IPL_A', 0x200000), ('EMC_IPL_B', 0x2F0000),
                              ('EAP_KBL', 0x1C000), ('Torus', 0x144000)]:
            if offset + 0x40 <= len(_current_dump):
                magic = _current_dump[offset:offset + 4]
                if magic == b'SLB2':
                    try:
                        data = _current_dump[offset:offset + 0x10000]
                        rb = SLB2Rebuilder.parse(data)
                        print(f'  Found SLB2 @ {hex(offset)} ({name}): {len(rb.entries)} entries')
                        rb.report()
                    except Exception as e:
                        print(f'  SLB2 @ {hex(offset)} ({name}): parse error - {e}')

    elif choice == '2':
        entries = {}
        print('  Enter entry name and file path (empty name to finish):')
        while True:
            name = input('    Entry name: ').strip()
            if not name:
                break
            path = input('    Data file: ').strip()
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    entries[name] = f.read()
                print(f'    Added {name}: {len(entries[name])} bytes')
            else:
                print('    File not found.')
        if entries:
            compress = input('  Compress with LZ4? (y/n): ').strip().lower() == 'y'
            data = rebuild_slb2(entries, compress=compress)
            out = input('  Output file: ').strip()
            if out:
                with open(out, 'wb') as f:
                    f.write(data)
                print(f'  Written {len(data)} bytes to {out}')

    elif choice == '3':
        if not _load_dump():
            return
        print('  Scanning for SLB2...')
        for offset in [0x200000, 0x2F0000, 0x1C000, 0x144000]:
            if offset + 0x40 <= len(_current_dump):
                if _current_dump[offset:offset + 4] == b'SLB2':
                    data = _current_dump[offset:offset + 0x10000]
                    try:
                        rb = SLB2Rebuilder.parse(data)
                        print()
                        print(f'  SLB2 @ {hex(offset)}:')
                        print(rb.report())
                    except Exception:
                        pass


# ======================================================================
# FEATURE: SMART DONOR MATCHER
# ======================================================================

def donor_match():
    _header('SMART DONOR MATCHER')
    if not os.path.isdir(DONORS_DIR):
        print(f'Donors directory not found: {DONORS_DIR}')
        return

    matcher = SmartDonorMatcher(DONORS_DIR, use_cache=False)
    print(f'  {info("Donors:")} {value(str(matcher.donor_count))}')
    print()

    # Auto-detect from loaded dump
    target_sku = None
    target_fw = None
    if _current_dump is not None:
        auto_sku = detect_sku(_current_dump)
        auto_fw = detect_fw_version(_current_dump)
        if auto_sku != 'Unknown':
            target_sku = auto_sku
            print(f'  {info("Detected SKU:")} {value(auto_sku)}')
        else:
            print(f'  {warn("SKU auto-detection failed")}')
        if auto_fw:
            target_fw = auto_fw
            print(f'  {info("Detected FW:")}  {value(auto_fw)}')
        else:
            print(f'  {warn("FW auto-detection failed")}')
        print()

    # Manual override if no dump loaded or detection failed
    if not target_sku:
        target_sku = input(f'  {info("SKU")} (e.g. CUH-2216A): ').strip().upper()
        if not target_sku:
            print(f'  {warn("SKU required.")}')
            return
    else:
        override = input(f'  {info("Override SKU/FW?")} (y/N): ').strip().lower()
        if override == 'y':
            target_sku = input(f'  {info("SKU")} (e.g. CUH-2216A): ').strip().upper()
            target_fw = input(f'  {info("FW")}  (e.g. 13.02): ').strip()
            if not target_sku:
                print(f'  {warn("SKU required.")}')
                return

    print(f'\n  {dim("Matching...")}')
    result = matcher.match(target_sku, target_fw if target_fw else None)
    print(matcher.format_match_report(result))

    if result.best and result.best.score > 50:
        copy = input(f'  {info("Copy best donor to dumps/?")} (y/n): ').strip().lower()
        if copy == 'y':
            import shutil
            dest = os.path.join(DUMPS_DIR, f'best_donor_{result.best.filename}')
            shutil.copy2(result.best.filepath, dest)
            print(f'  {ok("Copied:")} {value(dest)}')


def donor_list():
    _header('DONOR LIST')
    if not os.path.isdir(DONORS_DIR):
        print('Donors directory not found.')
        return
    matcher = SmartDonorMatcher(DONORS_DIR, use_cache=False)
    print(f'  {info("Total:")} {value(str(matcher.donor_count))} donors')
    print()
    print(f'  {head("SKU"):<14} {head("FW"):<8} {head("Model"):<7} {head("Region"):<7} {head("Size")}')
    print(f'  {dim("-" * 55)}')
    for d in sorted(matcher.get_donor_list(), key=lambda x: (x.model, x.sku)):
        if d.sku == 'UNKNOWN':
            model_colored = fail(f'{d.model:<7}')
            sku_colored = fail(f'{d.sku:<14}')
        elif d.model == 'Fat':
            model_colored = f'{C.GRN}{d.model:<7}{C.RST}'
            sku_colored = f'{C.GRN}{d.sku:<14}{C.RST}'
        elif d.model == 'Slim':
            model_colored = f'{C.CYN}{d.model:<7}{C.RST}'
            sku_colored = f'{C.CYN}{d.sku:<14}{C.RST}'
        elif d.model == 'Pro':
            model_colored = f'{C.MAG}{d.model:<7}{C.RST}'
            sku_colored = f'{C.MAG}{d.sku:<14}{C.RST}'
        else:
            model_colored = f'{d.model:<7}'
            sku_colored = f'{d.sku:<14}'
        fw_colored = value(f'{d.fw_version:<8}') if d.fw_version != 'Unknown' else fail(f'{d.fw_version:<8}')
        region_colored = dim(d.region) if d.region != 'Unknown' else fail(d.region)
        print(f'  {sku_colored} {fw_colored} {model_colored} {region_colored:<7} {d.size:,}')


# ======================================================================
# FEATURE: SMART AUTO REPAIR (v2)
# ======================================================================

def smart_repair():
    _header('SMART AUTO-REPAIR v2')
    if not _load_dump():
        return
    print()
    print(f'  {dim("Smart donor matcher with section-level repair.")}')
    print(f'  {dim("Console identity (IDPS/PSID) preserved.")}')
    print()
    fix = input(f'  {info("Fix warnings?")} (y/n): ').strip().lower() == 'y'
    print()
    repair = SmartAutoRepair(_current_dump, DONORS_DIR, FWS_DIR)
    applied = repair.repair_all(fix_warnings=fix)
    print()
    print(repair.get_report())
    if applied:
        save = input(f'  {info("Save repaired dump?")} (y/n): ').strip().lower()
        if save == 'y':
            out_name = f'repaired_{os.path.basename(_current_path)}'
            out_path = os.path.join(DUMPS_DIR, out_name)
            with open(out_path, 'wb') as f:
                f.write(repair.get_data())
            print(f'  {ok("Saved:")} {value(out_path)}')


# ======================================================================
# FEATURE: HYBRID AUTO REPAIR v2.1 (FW Blob → Donor Cascade)
# ======================================================================

def hybrid_repair():
    _header('HYBRID AUTO-REPAIR v2.1')
    if not _load_dump():
        return
    print()
    print(f'  {dim("Four-pass hybrid repair:")}')
    print(f'  {dim("  Pass 1: FW Blob (exact MD5 / FW range + type code)")}')
    print(f'  {dim("  Pass 2: Same-FW Donor (filtered by version)")}')
    print(f'  {dim("  Pass 3: Cross-Donor Cascade (fallback)")}')
    print(f'  {dim("  Pass 4: Byte-Level Patching (corrupt bytes only)")}')
    print()
    print(f'  {dim("Console identity (IDPS/PSID) preserved.")}')
    print()
    repair = HybridRepairV21(_current_dump, FWS_DIR, DONORS_DIR)
    applied = repair.repair_all()
    print()
    print(repair.get_report())
    if applied:
        save = input(f'  {info("Save repaired dump?")} (y/n): ').strip().lower()
        if save == 'y':
            out_name = f'v21_repaired_{os.path.basename(_current_path)}'
            out_path = os.path.join(DUMPS_DIR, out_name)
            with open(out_path, 'wb') as f:
                f.write(repair.get_data())
            print(f'  {ok("Saved:")} {value(out_path)}')


# ======================================================================
# FEATURE: HDD ANALYZER
# ======================================================================

def hdd_analysis():
    _header('HDD METADATA ANALYSIS')
    if not _load_dump():
        return
    print()
    analysis = analyze_hdd_metadata(_current_dump)
    report_raw = format_hdd_report(analysis)
    report_raw = report_raw.replace('\u2260', '!=')
    print(report_raw)

    # Check EAP key status
    key_primary = analysis.get('keys_primary_valid', False)
    key_backup = analysis.get('keys_backup_valid', False)

    if (not analysis['mirror_synced'] or
        analysis['warnings'] or
        (not key_primary and not key_backup)):
        fix = input(f'  {info("Sync/repair NVS metadata?")} (y/n): ').strip().lower()
        if fix == 'y':
            data = bytearray(_current_dump)
            donor_data = None

            # Try to load donor for EAP key if needed
            if not key_primary and not key_backup:
                use_donor = input(f'  {warn("HDD key blob corrupt")} - restore from donor? (y/n): ').strip().lower()
                if use_donor == 'y' and os.path.isdir(DONORS_DIR):
                    matcher = SmartDonorMatcher(DONORS_DIR)
                    sku = detect_sku(_current_dump)
                    fw = detect_fw_version(_current_dump)
                    result = matcher.match(sku, fw)
                    if result.best:
                        dpath = result.best.filepath
                        print(f'  {info("Using donor:")} {value(os.path.basename(dpath))} {dim(f"(score={result.best.score})")}')
                        with open(dpath, 'rb') as df:
                            donor_data = df.read()

            actions = repair_hdd_metadata(data, donor_data, DONORS_DIR)
            for a in actions:
                print(f'  {ok(a)}')
            if actions and 'FAILED' not in actions[0]:
                save = input(f'  {info("Save repaired dump?")} (y/n): ').strip().lower()
                if save == 'y':
                    out = os.path.join(DUMPS_DIR, f'nvs_fixed_{os.path.basename(_current_path)}')
                    with open(out, 'wb') as f:
                        f.write(data)
                    print(f'  {ok("Saved:")} {value(out)}')


def analyze_damage():
    _header('DAMAGE ANALYSIS')
    if not _load_dump():
        return
    from ps4nor.patchers.auto_repair import _region_healthy
    from ps4nor.v2_features.hdd_analyzer import analyze_hdd_metadata, format_hdd_report
    data = _current_dump
    print()
    print(f'  {head("Section"):<16} {head("Status"):<10} {head("Size"):<10} {head("Category"):<12}')
    print(f'  {dim("-" * 50)}')
    total = 0
    count = 0
    for name, start, end, cat in CRITICAL_REGIONS:
        if start >= len(data):
            continue
        actual_end = min(end, len(data))
        threshold = REGION_MIN_HEALTHY.get(name, 64)
        healthy = _region_healthy(data, start, actual_end, threshold)
        status = ok('OK') if healthy else fail('DAMAGED')
        size_kb = (actual_end - start) // 1024
        size_str = f'{size_kb}KB' if size_kb < 1024 else f'{size_kb//1024}MB'
        print(f'  {name:<16} {status:<10} {size_str:<10} {cat:<12}')
        if not healthy:
            total += 1
        count += 1
    if total:
        print(f'\n  {fail(f"Total damaged: {total}/{count}")}')
    else:
        print(f'\n  {ok(f"Total damaged: {total}/{count}")}')

    # Detailed HDD/NVS analysis
    print()
    hdd_a = analyze_hdd_metadata(data)
    r = format_hdd_report(hdd_a)
    r = r.replace('\u2260', '!=')
    print(r)


# ======================================================================
# FEATURE: GUIDED INTERACTIVE REPAIR
# ======================================================================

def guided_repair():
    _header('GUIDED INTERACTIVE REPAIR')
    if not _load_dump():
        return
    from ps4nor.patchers.auto_repair import _region_healthy, _region_empty
    from ps4nor.v2_features.hdd_analyzer import analyze_hdd_metadata, detect_eap_key_size, _is_valid_eap, _extract_hdd_info
    from ps4nor.v2_features.hdd_analyzer import HDD_KEY_MAGIC, HDD_KEY_BLOB, HDD_KEY_BACKUP_MAGIC, HDD_KEY_BACKUP_BLOB

    data = bytearray(_current_dump)
    IOFF = 0x1C4000  # NVS start

    print()
    issues = []
    data_out = bytearray(_current_dump)

    # 1 CRITICAL_REGIONS health
    for name, start, end, cat in CRITICAL_REGIONS:
        threshold = REGION_MIN_HEALTHY.get(name, 64)
        actual_end = min(end, len(data_out))
        if not _region_healthy(data_out, start, actual_end, threshold):
            sharable = SHARABLE_SECTIONS.get(name, False)
            fix_fn = None
            if sharable:
                fix_fn = lambda d=start, e=actual_end, nm=name: _copy_from_donor(data_out, d, e, nm, DONORS_DIR)
            issues.append({
                'desc': f'{name} ({cat}): DAMAGED',
                'fix': fix_fn,
            })

    # 2 NVS / HDD issues via analyze_hdd_metadata
    hdd = analyze_hdd_metadata(bytes(data_out))
    for w in hdd.get('warnings', []):
        if not any(w == iss['desc'] for iss in issues):
            issues.append({'desc': w, 'fix': None})

    # 3 HDD metadata sync
    meta1 = data_out[IOFF + 0x1000:IOFF + 0x1000 + 0x1000]
    meta2 = data_out[IOFF + 0xA000:IOFF + 0xA000 + 0x1000]
    if meta1 != meta2:
        h1 = sum(1 for b in meta1 if b not in (0, 0xFF)) > 32
        h2 = sum(1 for b in meta2 if b not in (0, 0xFF)) > 32
        if h1 and h2:
            issues.append({
                'desc': 'HDD metadata primary (0x1C5000) differs from mirror (0x1CE000)',
                'fix': lambda: _fix_hdd_meta_sync(data_out, IOFF),
            })

    # 4 CID CRC mismatch
    cid_crc1 = data_out[IOFF + 0x5000:IOFF + 0x5000 + 0x1000]
    cid_crc2 = data_out[IOFF + 0x8000:IOFF + 0x8000 + 0x1000]
    if cid_crc1 != cid_crc2:
        issues.append({
            'desc': 'CID CRC (0x1C9000) differs from mirror (0x1CC000)',
            'fix': lambda: _fix_cid_crc_sync(data_out, IOFF),
        })

    # 5 CID mismatch
    cid1 = data_out[IOFF + 0x6000:IOFF + 0x6000 + 0x1000]
    cid2 = data_out[IOFF + 0x9000:IOFF + 0x9000 + 0x1000]
    if cid1 != cid2:
        issues.append({
            'desc': 'CID (0x1CA000) differs from mirror (0x1CD000)',
            'fix': lambda: _fix_cid_sync(data_out, IOFF),
        })

    # 6 HDD info missing
    hi = _extract_hdd_info(data_out, 0x1C9C00)
    if not hi.get('has_data'):
        issues.append({'desc': 'No HDD model/serial data at 0x1C9C00', 'fix': None})

    # 7 EAP HDD key check
    eap_sz = detect_eap_key_size(bytes(data_out))
    if not _is_valid_eap(data_out, HDD_KEY_MAGIC, eap_sz):
        issues.append({
            'desc': 'EAP HDD key (0x1C9200) invalid or corrupt',
            'fix': lambda: _fix_eap_key(data_out, DONORS_DIR),
        })

    # Present issues
    if not issues:
        print(f'  {ok("No issues found — dump is healthy")}')
        return

    print(f'  {warn(f"Found {len(issues)} issue(s):")}')
    print()
    selected = []
    for i, iss in enumerate(issues, 1):
        desc = iss['desc']
        can_fix = iss['fix'] is not None
        status = ok('repairable') if can_fix else dim('no auto-fix')
        print(f'  [{i}/{len(issues)}] {desc}  ({status})')
        if can_fix:
            ans = input(f'      Repair? (y/n): ').strip().lower()
            if ans == 'y':
                selected.append(i)
                print(f'      {info("-> selected")}')
        print()

    # Apply selected fixes
    if not selected:
        print(f'  {dim("No repairs selected.")}')
        return

    repair_count = 0
    for i in selected:
        iss = issues[i - 1]
        try:
            iss['fix']()
            repair_count += 1
            print(f'  {ok(f"  [{i}] Fixed:")} {iss["desc"]}')
        except Exception as e:
            print(f'  {fail(f"  [{i}] Failed:")} {iss["desc"]} — {e}')

    print()
    print(f'  {ok(f"Repairs applied: {repair_count}/{len(selected)}")}')

    if repair_count:
        save = input(f'  {info("Save repaired dump?")} (y/n): ').strip().lower()
        if save == 'y':
            out_name = f'guided_{os.path.basename(_current_path)}'
            out_path = os.path.join(DUMPS_DIR, out_name)
            with open(out_path, 'wb') as f:
                f.write(data_out)
            print(f'  {ok("Saved:")} {value(out_path)}')

    # Offer NVS Regeneration as optional next step
    from ps4nor.v2_features.nvs_regen import (
        extract_board_id, format_board_id, board_id_match_level,
        nvs_regen_method1, nvs_regen_method3,
    )
    bid_t_guided = extract_board_id(bytes(data_out))
    bt_str_guided = format_board_id(bid_t_guided)
    print()
    ans = input(f'  {info("NVS Regeneration?")} Board ID={value(bt_str_guided)} (y/n): ').strip().lower()
    if ans == 'y':
        # Scan donors with Board ID + SmartDonorMatcher ranking
        try:
            from ps4nor.utils.helpers import detect_sku, detect_fw_version
            from ps4nor.v2_features.smart_donor import SmartDonorMatcher
            t_sku = detect_sku(bytes(data_out))
            t_fw = detect_fw_version(bytes(data_out))
            matcher = SmartDonorMatcher(DONORS_DIR, use_cache=False)
            scored = matcher.match(t_sku, t_fw).matches
        except Exception:
            scored = []

        donors_list = []
        seen_paths = set()
        for d in scored:
            if d.score <= 0 or d.filepath in seen_paths:
                continue
            seen_paths.add(d.filepath)
            try:
                with open(d.filepath, 'rb') as f:
                    raw = f.read()
                bd = extract_board_id(raw)
                bl = board_id_match_level(bid_t_guided, bd) if bid_t_guided and bd else 2
                donors_list.append((bl, -d.score, d.filename, d.filepath, bd))
            except Exception:
                continue
        # Extra none-scored
        for fname in sorted(os.listdir(DONORS_DIR)):
            if not fname.upper().endswith('.BIN'):
                continue
            fpath = os.path.join(DONORS_DIR, fname)
            if fpath in seen_paths:
                continue
            try:
                with open(fpath, 'rb') as f:
                    raw = f.read()
                if len(raw) != 0x2000000:
                    continue
                bd = extract_board_id(raw)
                bl = board_id_match_level(bid_t_guided, bd) if bid_t_guided and bd else 2
                donors_list.append((bl, 0, fname, fpath, bd))
            except Exception:
                continue

        donors_list.sort(key=lambda x: (x[0], x[1]))
        if not donors_list:
            print(f'  {dim("No valid donors.")}')
            return

        print(f'  {info("Top compatible donors:")}')
        board_labels = {0: ok('MATCH'), 1: warn('CLOSE'), 2: dim('DIFF')}
        for i, (bl, sc, fn, fp, bd) in enumerate(donors_list[:8], 1):
            bds = format_board_id(bd)
            print(f'    {ok(f"[{i}]")} {head(fn):20} Board={value(bds):26} {board_labels.get(bl, "?")}')
        print()

        # Auto or manual
        use_auto = input(f'  {info("Auto-select best?")} (y/n): ').strip().lower()
        if use_auto == 'y':
            bl, sc, fname, fpath, bd = donors_list[0]
            print(f'  Selected: {value(fname)}')
            donor_data = open(fpath, 'rb').read()
            level = bl
        else:
            try:
                sel = int(input(f'  {info("Select")} (1-{len(donors_list)}): ').strip())
                bl, sc, fname, fpath, bd = donors_list[sel - 1]
                donor_data = open(fpath, 'rb').read()
                level = bl
            except (ValueError, IndexError):
                print(f'  {dim("Invalid.")}')
                return

        bd_str = format_board_id(bd)
        lmap = {0: ok('MATCH'), 1: warn('CLOSE'), 2: dim('DIFF')}
        print(f'  Board: target={value(bt_str_guided)}  donor={value(bd_str)}  ({lmap.get(level, "?")})')

        ch = input(f'  {info("Method")} A=Auto 1=Safe 2=Blind 3=Combined S=Skip: ').strip().lower()
        if ch in ('', 'a'):
            result, rpt = (nvs_regen_method3 if level == 0 else nvs_regen_method1)(bytes(data_out), donor_data)
        elif ch == '1':
            result, rpt = nvs_regen_method1(bytes(data_out), donor_data)
        elif ch == '3':
            result, rpt = nvs_regen_method3(bytes(data_out), donor_data)
        else:
            print(f'  {dim("Skipped.")}')
            return

        for line in rpt:
            print(f'  {line}')
        data_out = bytearray(result)
        print(f'  {ok("NVS regeneration applied.")}')

        out_name = f'nvs_regen_{os.path.basename(_current_path)}'
        out_path = os.path.join(DUMPS_DIR, out_name)
        with open(out_path, 'wb') as f:
            f.write(data_out)
        print(f'  {ok("Saved:")} {value(out_path)}')


# ── helper fix functions ──────────────────────────────────────────

def _copy_from_donor(data, start, end, name, donors_dir):
    """Copy a region from the first valid donor."""
    import os
    if not os.path.isdir(donors_dir):
        raise RuntimeError('Donors directory not found')
    for fname in sorted(os.listdir(donors_dir)):
        if not fname.upper().endswith('.BIN'):
            continue
        fpath = os.path.join(donors_dir, fname)
        with open(fpath, 'rb') as f:
            d = f.read()
        if len(d) >= end:
            chunk = d[start:end]
            nz = sum(1 for b in chunk if b not in (0, 0xFF))
            if nz > 32:
                data[start:end] = chunk
                return
    raise RuntimeError(f'No valid donor for {name}')

def _fix_hdd_meta_sync(data, off):
    meta1 = data[off + 0x1000:off + 0x1000 + 0x1000]
    meta2 = data[off + 0xA000:off + 0xA000 + 0x1000]
    h1 = sum(1 for b in meta1 if b not in (0, 0xFF)) > 32
    h2 = sum(1 for b in meta2 if b not in (0, 0xFF)) > 32
    if h1 and h2:
        data[off + 0xA000:off + 0xA000 + 0x1000] = meta1
    elif h1 and not h2:
        data[off + 0xA000:off + 0xA000 + 0x1000] = meta1
    elif not h1 and h2:
        data[off + 0x1000:off + 0x1000 + 0x1000] = meta2

def _fix_cid_crc_sync(data, off):
    data[off + 0x8000:off + 0x8000 + 0x1000] = data[off + 0x5000:off + 0x5000 + 0x1000]

def _fix_cid_sync(data, off):
    data[off + 0x9000:off + 0x9000 + 0x1000] = data[off + 0x6000:off + 0x6000 + 0x1000]

def _fix_eap_key(data, donors_dir):
    """Restore EAP HDD key from backup or donor."""
    from ps4nor.v2_features.hdd_analyzer import detect_eap_key_size, _is_valid_eap
    from ps4nor.v2_features.hdd_analyzer import HDD_KEY_MAGIC, HDD_KEY_BLOB, HDD_KEY_BACKUP_MAGIC, HDD_KEY_BACKUP_BLOB
    sz = detect_eap_key_size(bytes(data))
    p = _is_valid_eap(data, HDD_KEY_MAGIC, sz)
    b = _is_valid_eap(data, HDD_KEY_BACKUP_MAGIC, sz)
    if b and not p:
        data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + sz] = data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + sz]
        return
    if p and not b:
        data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + sz] = data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + sz]
        return
    if not p and not b and os.path.isdir(donors_dir):
        for fname in sorted(os.listdir(donors_dir)):
            if not fname.upper().endswith('.BIN'):
                continue
            fpath = os.path.join(donors_dir, fname)
            with open(fpath, 'rb') as f:
                d = f.read()
            dsz = detect_eap_key_size(d)
            if _is_valid_eap(d, HDD_KEY_MAGIC, dsz):
                data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + sz] = d[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + dsz][:4 + sz]
                data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + sz] = d[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + dsz][:4 + sz]
                return
    raise RuntimeError('No valid source for EAP key')


# ======================================================================
# FEATURE: REBUILD DATABASE
# ======================================================================

def rebuild_db():
    _header('REBUILD DATABASE')
    print(f'  {dim("Rescanning donors and FW blobs...")}')
    print()

    # Clear donor cache
    cache_path = os.path.join(DONORS_DIR, '.donor_cache.json')
    if os.path.exists(cache_path):
        os.remove(cache_path)
        print(f'  {ok("Donor cache cleared.")}')
    else:
        print(f'  {info("No donor cache found.")}')

    # Rescan donors
    print(f'  {dim("Scanning donors...")}', end=' ')
    matcher = SmartDonorMatcher(DONORS_DIR, use_cache=False)
    print(f'{value(str(matcher.donor_count))} donors found')

    # Count FW blobs
    blob_count = 0
    if os.path.isdir(FWS_DIR):
        for root, dirs, files in os.walk(FWS_DIR):
            for f in files:
                if f.endswith('.2bls'):
                    blob_count += 1
    print(f'  {info("FW blobs:")} {value(str(blob_count))}')

    dir_count = 0
    for entry in os.scandir(FWS_DIR):
        if entry.is_dir():
            dir_count += 1
    print(f'  {info("FW sections:")} {value(dir_count)}')

    print()
    items = [
        ('Donors', matcher.donor_count),
        ('FW blobs (.2bls)', blob_count),
        ('FW section dirs', dir_count),
    ]
    if os.path.isdir(DUMPS_DIR):
        dump_count = len([f for f in os.listdir(DUMPS_DIR) if f.endswith(('.bin', '.BIN', '.nor', '.NOR'))])
        items.append(('Dumps in folder', dump_count))
    print(f'  {head("Database rebuild complete.")}')
    for name, count in items:
        print(f'    {info(name+":")} {value(str(count))}')


# ======================================================================
# FEATURE: CREDITS
# ======================================================================

def show_credits():
    _header('CREDITS & THANKS')
    print(f'  {brand("PS4 NOR Validator Pro v" + __version__)}')
    print(f'  {dim("by ISLAM JAMEL")}')
    print()
    print(f'  {title("=== Special Thanks ===")}')
    print()
    print(f'  {info("All open-source researchers")} who shared their knowledge')
    print(f'  and tools with the PS4 scene.')
    print()
    print(f'  {info("Friends and colleagues")} for continuous support, testing,')
    print(f'  and valuable feedback.')
    print()
    print(f'  {title("=== Arabic Maintenance Group BGA ===")}')
    print(f'  Thank you for your support, collaboration, and dedication')
    print(f'  to the hardware repair community.')
    print()
    print(f'  {title("=== Personal Thanks ===")}')
    print()
    print(f'  {info("My brother Abu Mohammed Raed Absiso")}')
    print(f'  A friend who stood by me and supported me through')
    print(f'  the hardest times. This would not have been possible without you.')
    print()


# ======================================================================
# FEATURE: NVS REGENERATION (3 Methods)
# ======================================================================

def nvs_regeneration():
    _header('NVS REGENERATION')
    if not _load_dump():
        return
    from ps4nor.v2_features.nvs_regen import (
        extract_board_id, format_board_id, board_id_match_level,
        nvs_regen_method1, nvs_regen_method2, nvs_regen_method3,
    )
    from ps4nor.utils.helpers import detect_sku, detect_fw_version

    data = bytearray(_current_dump)
    target_name = os.path.basename(_current_path) if _current_path else 'target'
    bid_t = extract_board_id(bytes(data))
    bt_str = format_board_id(bid_t)
    target_sku = detect_sku(bytes(data))
    target_fw = detect_fw_version(bytes(data))

    print(f'  Target: {value(target_name)}  SKU={value(target_sku)}  FW={value(target_fw)}')
    print(f'  Board ID: {value(bt_str)}')
    print()

    if not os.path.isdir(DONORS_DIR):
        print(f'  {fail("Donors directory not found.")}')
        return

    # Scan donors: rank by SmartDonorMatcher, add Board ID info
    try:
        from ps4nor.v2_features.smart_donor import SmartDonorMatcher
        matcher = SmartDonorMatcher(DONORS_DIR, use_cache=False)
        result = matcher.match(target_sku, target_fw)
        scored = result.matches
    except Exception:
        scored = []

    # Also scan remaining BIN files not in matcher
    seen = set(d.filepath for d in scored)
    donors_extra = []
    for fname in sorted(os.listdir(DONORS_DIR)):
        if not fname.upper().endswith('.BIN'):
            continue
        fpath = os.path.join(DONORS_DIR, fname)
        if fpath in seen:
            continue
        try:
            with open(fpath, 'rb') as f:
                d = f.read()
            if len(d) != 0x2000000:
                continue
            bd = extract_board_id(d)
            bl = board_id_match_level(bid_t, bd) if bid_t and bd else 2
            sku = detect_sku(d)
            fw = detect_fw_version(d)
            donors_extra.append({
                'filepath': fpath, 'filename': fname,
                'sku': sku, 'fw': fw, 'board_id': bd, 'board_level': bl,
                'score': 0.0,
            })
        except Exception:
            continue

    # Convert scored to dicts with Board ID info
    donors = []
    for d in scored:
        if d.score <= 0:
            continue
        try:
            fpath = d.filepath
            with open(fpath, 'rb') as f:
                raw = f.read()
            bd = extract_board_id(raw)
            bl = board_id_match_level(bid_t, bd) if bid_t and bd else 2
            donors.append({
                'filepath': fpath, 'filename': d.filename,
                'sku': d.sku, 'fw': d.fw_version, 'score': d.score,
                'board_id': bd, 'board_level': bl,
            })
        except Exception:
            continue
    donors.extend(donors_extra)

    # Sort: board match level (best first), then score descending
    donors.sort(key=lambda x: (x['board_level'], -x['score']))

    if not donors:
        print(f'  {fail("No valid 32MB donor files found.")}')
        return

    # Display ranked donors
    board_labels = {0: ok('MATCH'), 1: warn('CLOSE'), 2: dim('DIFF')}
    print(f'  {info("Compatible Donors (by Board ID + SKU/FW score):")}')
    print(f'  {"":4} {"Donor":20} {"Board ID":26} {"SKU":14} {"FW":10} {"Board":8} {"Score":8}')
    print(f'  {"":4} {"-"*20} {"-"*26} {"-"*14} {"-"*10} {"-"*8} {"-"*8}')
    for i, d in enumerate(donors, 1):
        bd_str = format_board_id(d['board_id'])
        label = board_labels.get(d['board_level'], dim('?'))
        score_str = f"{d['score']:.0f}" if d['score'] > 0 else dim('-')
        print(f'  [{i:2}] {d["filename"]:20} {value(bd_str):26} {d["sku"]:14} {d["fw"]:10} {label:8} {score_str:8}')
    print()

    # Auto or manual selection
    ans = input(f'  {info("Auto-select best donor?")} (y/n): ').strip().lower()
    if ans == 'y':
        # Pick best: Board ID match first, then highest score
        best = donors[0]
        print(f'  Auto-selected: {value(best["filename"])} (Board: {format_board_id(best["board_id"])}, SKU={best["sku"]}, FW={best["fw"]})')
        donor_data = open(best['filepath'], 'rb').read()
        donor_name = best['filename']
    else:
        try:
            sel = int(input(f'  {info("Select donor")} (1-{len(donors)}): ').strip())
            donor_data = open(donors[sel - 1]['filepath'], 'rb').read()
            donor_name = donors[sel - 1]['filename']
        except (ValueError, IndexError):
            print(f'  {fail("Invalid selection.")}')
            return

    bid_d = extract_board_id(donor_data)
    bd_str = format_board_id(bid_d)
    level = board_id_match_level(bid_t, bid_d) if bid_t and bid_d else 2
    lmap = {0: ok('MATCH'), 1: warn('CLOSE'), 2: dim('DIFFERENT')}

    print()
    print(f'  {info("Board ID:")} target={value(bt_str)}  donor={value(bd_str)}  ({lmap.get(level, "?")})')

    # Auto-pick method
    print(f'  {info("Regeneration method:")}')
    print(f'    {dim("[A]")} Auto — picks best method based on Board ID match')
    print(f'    {dim("[1]")} Method 1 (Accurate Bytes) — safe, preserves identity')
    print(f'    {dim("[2]")} Method 2 (Blind Copy) — last half from donor')
    print(f'    {dim("[3]")} Method 3 (Combined 1+2) — most aggressive')
    print(f'    {dim("[S]")} Skip')

    choice = input(f'  {info("Choice")} (A/1/2/3/S): ').strip().lower()

    if choice in ('', 'a'):
        if level == 0:
            result, report = nvs_regen_method3(bytes(data), donor_data)
        else:
            result, report = nvs_regen_method1(bytes(data), donor_data)
        print(f'  Auto-chose {"Method 3" if level == 0 else "Method 1"} (Board ID {"match" if level == 0 else "differ"})')
    elif choice == '1':
        result, report = nvs_regen_method1(bytes(data), donor_data)
    elif choice == '2':
        result, report = nvs_regen_method2(bytes(data), donor_data)
    elif choice == '3':
        result, report = nvs_regen_method3(bytes(data), donor_data)
    else:
        print(f'  {dim("Skipped.")}')
        return

    for line in report:
        print(f'  {line}')
    print(f'  {ok("NVS regeneration applied.")}')

    out_name = f'nvs_regen_{target_name}'
    out_path = os.path.join(DUMPS_DIR, out_name)
    with open(out_path, 'wb') as f:
        f.write(result)
    print(f'  {ok("Saved:")} {value(out_path)}')


# ======================================================================
# FEATURE: DOWNGRADE ASSISTANT
# ======================================================================

def downgrade_assistant():
    _header('DOWNGRADE ASSISTANT')

    # ── Step 1: Scan all BIN files in revert/ ──
    nor_candidates = []
    syscon_candidates = []
    seen = set()

    # Walk through revert/ recursively
    for root_dir, dirs, files in os.walk(REVERT_DIR):
        for fname in sorted(files):
            if not fname.upper().endswith('.BIN'):
                continue
            fpath = os.path.join(root_dir, fname)
            if fpath in seen:
                continue
            seen.add(fpath)
            try:
                with open(fpath, 'rb') as f:
                    d = f.read()
                sz = len(d)
                rel = os.path.relpath(fpath, REVERT_DIR)
                if sz in (0x40000, 0x80000):
                    syscon_candidates.append((rel, fpath, d))
                elif sz == 0x2000000:
                    nor_candidates.append((rel, fpath, d))
            except Exception:
                continue

    if not nor_candidates:
        print(f'  {warn("No 32MB NOR dumps in revert/ folder.")}')
        print(f'  {dim("Place your NOR (32MB) + Syscon (256KB) dumps in:")}')
        print(f'  {dim("  revert/<project>/ or revert/*.bin")}')
        print()
        # Fallback: use loaded dump
        if _current_path:
            ans = input(f'  {info("Use currently loaded dump as NOR?")} (y/n): ').strip().lower()
            if ans == 'y':
                # Prompt user to copy it to revert/
                import shutil
                pname = input(f'  {info("Project name to save as")}: ').strip()
                if pname:
                    proj_dir = os.path.join(REVERT_DIR, pname)
                    os.makedirs(proj_dir, exist_ok=True)
                    dest = os.path.join(proj_dir, 'nor.bin')
                    shutil.copy2(_current_path, dest)
                    print(f'  {ok("Copied to:")} {dest}')
                    # Re-scan
                    with open(dest, 'rb') as f:
                        d = f.read()
                    nor_candidates.append((os.path.join(pname, 'nor.bin'), dest, d))
        if not nor_candidates:
            return

    # ── Step 2: Select NOR ──
    print(f'  {info("Select NOR dump (32MB):")}')
    for i, (rel, fpath, d) in enumerate(nor_candidates, 1):
        from ps4nor.utils.helpers import detect_sku, detect_fw_version
        sku = detect_sku(d)
        fw = detect_fw_version(d)
        fw_s = fw if fw else '?'
        print(f'    {ok(f"[{i}]")} {head(rel)}  {dim(f"({sku}, FW {fw_s})")}')
    print()
    sel = input(f'  {info("Choose NOR")} (1-{len(nor_candidates)}): ').strip()
    try:
        nor_rel, nor_path, nor_data = nor_candidates[int(sel) - 1]
    except (ValueError, IndexError):
        print(f'  {fail("Invalid selection.")}')
        return
    print(f'  {ok("NOR:")} {nor_rel}')
    from ps4nor.utils.helpers import detect_sku, detect_fw_version
    print(f'  {dim("SKU:")} {detect_sku(nor_data)}  {dim("FW:")} {detect_fw_version(nor_data)}')
    print()

    # ── Step 3: Select Syscon ──
    if not syscon_candidates:
        print(f'  {warn("No Syscon dumps (256KB / 512KB) found in revert/.")}')
        print(f'  {dim("Will proceed without Syscon patching.")}')
        syscon_data = None
    else:
        print(f'  {info("Select Syscon dump (256KB / 512KB):")}')
        for i, (rel, fpath, d) in enumerate(syscon_candidates, 1):
            from ps4nor.patchers.syscon_patcher import SysconSNVSPatcher
            sp = SysconSNVSPatcher(d)
            snvs_info = sp.analyze_snvs()
            recs = snvs_info.get('fw_record_count', 0)
            entries = snvs_info.get('total_entries', 0)
            sz_kb = len(d) // 1024
            print(f'    {ok(f"[{i}]")} {head(rel)}  {dim(f"({sz_kb}KB, {entries} entries, {recs} FW recs)")}')
        print()
        sel = input(f'  {info("Choose Syscon")} (1-{len(syscon_candidates)}): ').strip()
        try:
            sc_rel, sc_path, syscon_data = syscon_candidates[int(sel) - 1]
            print(f'  {ok("Syscon:")} {sc_rel}')
        except (ValueError, IndexError):
            print(f'  {fail("Invalid selection.")}')
            return

    # ── Step 3: Show analysis ──
    from ps4nor.v2_features.downgrade_assistant import DowngradeAssistant
    da = DowngradeAssistant(nor_data, syscon_data, FWS_DIR, DONORS_DIR)
    analysis = da.analyze()

    # Device identity match check
    match = da.check_device_match()
    print()
    print(f'  {title("=== Device Identity Check ===")}')
    print(f'  Board ID:  {value(match["board_id_hex"]) if match["board_id_hex"] else dim("N/A")}')
    print(f'  MAC:       {value(match["mac_str"]) if match["mac_str"] else dim("N/A")}')
    print(f'  Serial:    {value(match["serial"]) if match["serial"] else dim("N/A")}')
    print(f'  NOR FW:    {value(match["nor_fw"]) if match["nor_fw"] else dim("Unknown")}')
    print(f'  Syscon FW: {value(match["syscon_fw"])}')
    scarv = match.get('syscon_arv', -1)
    scchip = match.get('syscon_chip', '?')
    if scarv >= 0:
        print(f'  Syscon:    {dim(f"{scchip} ARV={scarv}")}')
    arv_st = match.get('arv_status')
    ad = match.get('arv_detail', '')
    if arv_st == 'matched':
        print(f'  {ok(f"ARV match: {ad}")}')
    elif arv_st == 'mismatch':
        print(f'  {warn(f"ARV mismatch: {ad}")}')
        ans = input(f'  {warn("Syscon may not be from this NOR! Continue anyway?")} (y/n): ').strip().lower()
        if ans != 'y':
            print(f'  {dim("Aborted.")}')
            return
    if match['matched'] is True and arv_st != 'mismatch':
        print(f'  {ok("Device match: MATCHED")}')
    elif match['matched'] is False and not arv_st:
        print(f'  {warn("Device match: MISMATCH (Syscon FW != NOR FW)")}')
        ans = input(f'  {warn("Syscon may not be from this NOR! Continue?")} (y/n): ').strip().lower()
        if ans != 'y':
            print(f'  {dim("Aborted.")}')
            return
    elif arv_st != 'mismatch':
        print(f'  {dim("Device match: Unknown syscon — cannot verify pair")}')
        if syscon_data:
            ans = input(f'  {info("Proceed anyway?")} (y/n): ').strip().lower()
            if ans != 'y':
                print(f'  {dim("Aborted.")}')
                return

    print()
    print(da.get_report())
    print()

    target_slot = analysis.get('target_slot')
    nor = analysis.get('nor', {})
    current_fw = nor.get('fw_current', '?')

    if target_slot:
        target_fw = analysis.get('target_fw', '?')
        print(f'  {ok(f"Downgrade: FW {current_fw} -> {target_fw} (CoreOS_{target_slot})")}')
    else:
        print(f'  {warn("Both slots have same FW — CORE_SWCH flip may still work")}')

    # ── Step 4: Choose operations (auto/manual mix) ──
    print()
    print(f'  {info("Operations:")}')
    ops = {
        '1': 'CORE_SWCH flip (swap CoreOS slot)',
        '2': 'UART enable (0x1C931F)',
        '3': 'Syscon SNVS patch (remove last FW record)' if syscon_data else 'Syscon SNVS patch — NO SYSCON',
        '4': 'EAP_KBL replacement (match target FW)',
    }
    for k, desc in ops.items():
        print(f'    [{k}] {desc}')
    if syscon_data:
        print(f'    {info("[R]")} Rebuild Syscon (WeeTools keep-same-FW) instead of patch')

    print()
    ans = input(f'  {info("Auto mode (recommended) or manual?")} (a/m): ').strip().lower()
    if ans == 'a':
        do_core_swch = True
        do_uart = True
        do_syscon_patch = syscon_data is not None
        do_wee_rebuild = False
        do_eap = input(f'  {info("Replace EAP_KBL with target FW blob?")} (y/n): ').strip().lower() == 'y'
        print(f'  {dim("Auto selected: CORE_SWCH + UART")}' + (' + Syscon patch' if do_syscon_patch else '') + (' + EAP_KBL' if do_eap else ''))
    else:
        do_core_swch = input(f'  {info("CORE_SWCH flip?")} (y/n): ').strip().lower() == 'y'
        do_uart = input(f'  {info("UART enable?")} (y/n): ').strip().lower() == 'y'
        do_syscon_patch = False
        do_wee_rebuild = False
        if syscon_data:
            sc_ch = input(f'  {info("Syscon: [P]atch or [R]ebuild or [S]kip?")} (p/r/s): ').strip().lower()
            if sc_ch == 'p':
                do_syscon_patch = True
            elif sc_ch == 'r':
                do_wee_rebuild = True
        do_eap = input(f'  {info("Replace EAP_KBL?")} (y/n): ').strip().lower() == 'y'

    # Handle WeeTools rebuild (applied to syscon before proceed)
    if do_wee_rebuild and syscon_data:
        from ps4nor.v2_features.syscon_regen import wee_rebuild
        rebuilt_sc, wee_rpt = wee_rebuild(syscon_data)
        if rebuilt_sc is not None:
            print()
            for line in wee_rpt.split('\n'):
                print(f'  {line}')
            syscon_data = rebuilt_sc
            print(f'  {ok("Syscon rebuilt with WeeTools method.")}')
            # Update DA with rebuilt syscon
            from ps4nor.v2_features.downgrade_assistant import DowngradeAssistant
            da = DowngradeAssistant(nor_data, syscon_data, FWS_DIR, DONORS_DIR)

    # ── Step 5: Apply ──
    if not (do_core_swch or do_uart or do_syscon_patch or do_eap or do_wee_rebuild):
        print(f'  {dim("No operations selected.")}')
        return

    nor_result, syscon_result, applied = da.downgrade(
        replace_eap=do_eap, enable_uart=do_uart, patch_syscon=do_syscon_patch
    )

    print()
    for msg in da.report:
        print(f'  {msg}')
    applied_str = ', '.join(applied)
    print(f'  {ok(f"Applied: {applied_str}")}')

    # ── Step 6: Save results alongside NOR ──
    nor_out_dir = os.path.dirname(nor_path)
    nor_out = os.path.join(nor_out_dir, 'nor_downgraded.bin')
    with open(nor_out, 'wb') as f:
        f.write(nor_result)
    print(f'  {ok("Saved NOR:")} {value(nor_out)}')

    if syscon_result:
        sc_out = os.path.join(nor_out_dir, 'syscon_downgraded.bin')
        with open(sc_out, 'wb') as f:
            f.write(syscon_result)
        print(f'  {ok("Saved Syscon:")} {value(sc_out)}')
    elif do_wee_rebuild:
        sc_out = os.path.join(nor_out_dir, 'syscon_rebuilt.bin')
        with open(sc_out, 'wb') as f:
            f.write(syscon_data)
        print(f'  {ok("Saved Rebuilt Syscon:")} {value(sc_out)}')
    elif do_syscon_patch:
        print(f'  {warn("Syscon SNVS patch skipped (less than 2 FW records).")}')

    print()
    print(f'  {title("=== Instructions ===")}')
    print(f'  {info("1.")} Write {value(nor_out)} to NOR')
    if syscon_result:
        print(f'  {info("2.")} Write {value(sc_out)} to Syscon')
    print(f'  {info("3.")} Power cycle console')
    print(f'  {ok("Done.")}')


# ======================================================================
# FEATURE: SYSCON REGENERATION
# ======================================================================

def syscon_rebuild():
    _header('SYSCON REGENERATION')

    print(f'  {info("1.")} Regenerate from donor (syscon_donors/)')
    print(f'  {info("2.")} WeeTools Rebuild (keep same FW, clean SNVS)')
    print(f'  {info("3.")} Full rebuild from NOR (damaged syscon, uses ARV→FW mapping)')
    print(f'  {info("4.")} Analyze & Repair Corrupted Syscon (standalone)')
    print()
    mode = input(f'  {info("Choice")} (1/2/3/4): ').strip()

    if mode == '4':
        syscon_analyze_repair()
        return

    if mode == '3':
        # Full rebuild from NOR — Scenario A: damaged syscon
        if not _current_dump:
            print(f'  {warn("No NOR dump loaded. Load one first (L).")}')
            return

        syscon = _load_syscon()
        if not syscon:
            print(f'  {warn("Cannot extract Syscon from loaded dump.")}')
            print(f'  {dim("Dump must be 32MB to extract Syscon.")}')
            return

        from ps4nor.v2_features.syscon_regen import syscon_rebuild_from_nor
        result, report = syscon_rebuild_from_nor(
            _current_dump, syscon,
            syscon_donors_dir=SYSCON_DONORS_DIR
        )
        if result is None:
            print(f'  {fail(f"Rebuild failed: {report}")}')
            return

        print()
        for line in report.split('\n'):
            print(f'  {line}')

        # Check ARV in result
        from ps4nor.v2_features.syscon_fw_db import format_syscon_report
        print()
        print(format_syscon_report(result))

        # Save
        out_dir = os.path.dirname(_current_path) if _current_path else DUMPS_DIR
        base = os.path.splitext(os.path.basename(_current_path))[0]
        out_path = os.path.join(out_dir, f'{base}_syscon_rebuilt.bin')
        with open(out_path, 'wb') as f:
            f.write(result)
        print(f'  {ok("Saved Syscon:")} {value(out_path)}')

        from ps4nor.patchers.syscon_patcher import SysconSNVSPatcher
        sp = SysconSNVSPatcher(result)
        snvs_info = sp.analyze_snvs()
        recs = snvs_info['fw_record_count']; ents = snvs_info['total_entries']
        print(f'  {dim(f"FW records: {recs}, entries: {ents}")}')
        print(f'  {ok("Done.")}')
        return

    if mode == '2':
        # WeeTools rebuild mode
        if not _current_dump:
            print(f'  {warn("No NOR dump loaded. Load one first (L).")}')
            return

        syscon = _load_syscon()
        if not syscon:
            print(f'  {warn("Cannot extract Syscon from loaded dump.")}')
            print(f'  {dim("Dump must be 32MB to extract Syscon.")}')
            return

        from ps4nor.v2_features.syscon_regen import wee_rebuild
        result, report = wee_rebuild(syscon)
        if result is None:
            print(f'  {fail(f"Rebuild failed: {report}")}')
            return

        for line in report.split('\n'):
            print(f'  {line}')

        # Save
        out_dir = os.path.dirname(_current_path) if _current_path else DUMPS_DIR
        base = os.path.splitext(os.path.basename(_current_path))[0]
        out_path = os.path.join(out_dir, f'{base}_syscon_rebuilt.bin')
        with open(out_path, 'wb') as f:
            f.write(result)
        print(f'  {ok("Saved Syscon:")} {value(out_path)}')

        from ps4nor.patchers.syscon_patcher import SysconSNVSPatcher
        sp = SysconSNVSPatcher(result)
        snvs_analysis = sp.analyze_snvs()
        recs = snvs_analysis['fw_record_count']; ents = snvs_analysis['total_entries']
        print(f'  {dim(f"FW records: {recs}, entries: {ents}")}')
        print(f'  {ok("Done.")}')
        return

    # Original donor-based mode
    from ps4nor.v2_features.syscon_regen import SysconDonorDB, syscon_regenerate, detect_target_nor
    from ps4nor.patchers.syscon_patcher import SysconSNVSPatcher

    if not _current_dump:
        print(f'  {warn("No NOR dump loaded. Load one first (L).")}')
        return

    db = SysconDonorDB(SYSCON_DONORS_DIR)
    donors = db.scan()
    if not donors:
        print(f'  {warn("No syscon donors found in syscon_donors/.")}')
        return

    nr_info = detect_target_nor(_current_dump)
    print(f'  Target: {value(os.path.basename(_current_path)) if _current_path else "loaded dump"}')
    print(f'  SKU: {value(nr_info["sku"])}  FW: {value(nr_info["fw"])}')
    if nr_info['board_id']:
        print(f'  Board ID: {value(nr_info["board_id"])}')
    if nr_info['mac']:
        print(f'  MAC: {value(nr_info["mac"])}')
    print()

    ranked = db.match(_current_dump)
    if not ranked:
        print(f'  {fail("No compatible syscon donor found.")}')
        return

    print(f'  {info("Available syscon donors (ranked):")}')
    for i, d in enumerate(ranked[:20], 1):
        score_str = value(str(d.match_score)) if d.match_score >= 0 else dim('NA')
        print(f'    {ok(f"[{i}]")} {head(d.filename)}  '
              f'{dim(f"({d.fw_count} FW recs, {d.size//1024}KB, score={score_str}, {d.match_reason})")}')

    if len(ranked) > 20:
        print(f'    {dim(f"... and {len(ranked) - 20} more")}')

    print()
    sel = input(f'  {info("Choose donor")} (1-{min(len(ranked), 20)}): ').strip()
    try:
        chosen = ranked[int(sel) - 1]
    except (ValueError, IndexError):
        print(f'  {fail("Invalid selection.")}')
        return

    print(f'  Selected: {head(chosen.filename)}')
    print()

    method_ch = input(f'  {info("Method")} (A=auto/Method A, B=Method B): ').strip().lower()
    method = 'B' if method_ch == 'b' else 'auto'

    try:
        with open(chosen.filepath, 'rb') as f:
            donor_data = f.read()
    except Exception as e:
        print(f'  {fail(f"Error reading donor: {e}")}')
        return

    result, report = syscon_regenerate(_current_dump, donor_data, method=method)
    if result is None:
        print(f'  {fail(f"Regeneration failed: {report}")}')
        return

    for line in report.split('\n'):
        print(f'  {line}')

    out_dir = os.path.dirname(_current_path) if _current_path else DUMPS_DIR
    base_name = os.path.splitext(os.path.basename(chosen.filepath))[0]
    out_path = os.path.join(out_dir, f'{base_name}_regen.bin')
    with open(out_path, 'wb') as f:
        f.write(result)
    print(f'  {ok("Saved:")} {value(out_path)}')

    if _current_dump and len(_current_dump) > 0:
        regen_sp = SysconSNVSPatcher(result)
        si = regen_sp.analyze_snvs()
        rec_cnt2 = si['fw_record_count']; print(f'  {dim(f"FW records: {rec_cnt2}")}')

    print(f'  {ok("Done.")}')


# ======================================================================
# FEATURE: SYSCON ANALYZE & REPAIR
# ======================================================================

def syscon_analyze_repair():
    _header('SYSCON ANALYSIS & REPAIR')

    # Step 1: Browse for syscon file (standalone)
    print(f'  {info("Select a corrupted syscon dump file...")}')
    print(f'  {dim("File must be 256KB or 512KB.")}')
    syscon_path = browse_file('Syscon dump (*.bin)', DUMPS_DIR)
    if not syscon_path:
        print(f'  {warn("No file selected.")}')
        return

    try:
        with open(syscon_path, 'rb') as f:
            syscon_data = f.read()
    except Exception as e:
        print(f'  {fail(f"Error reading file: {e}")}')
        return

    if len(syscon_data) not in (0x40000, 0x80000):
        print(f'  {fail(f"Invalid size: {len(syscon_data)} bytes (expected 256KB or 512KB)")}')
        return

    print(f'  {ok("Loaded:")} {head(os.path.basename(syscon_path))} {dim(f"({len(syscon_data)//1024}KB)")}')

    # Step 2: Ask for optional NOR
    nor_data = None
    nor_path = None
    ans = input(f'  {info("Do you have a NOR dump from the same device?")} (y/n): ').strip().lower()
    if ans == 'y':
        nor_path = browse_file('NOR dump (*.bin)', DUMPS_DIR)
        if nor_path:
            try:
                with open(nor_path, 'rb') as f:
                    nor_data = f.read()
                print(f'  {ok("Loaded NOR:")} {head(os.path.basename(nor_path))}')
            except Exception as e:
                print(f'  {warn(f"Could not read NOR: {e}")}')
                nor_data = None

    # Step 3: Run analysis
    print()
    print(f'  {dim("Analyzing syscon...")}')
    from ps4nor.v2_features.syscon_analyzer import analyze_syscon, format_analysis_report, REPAIR_LEVELS
    analysis = analyze_syscon(syscon_data, nor_data)
    print(format_analysis_report(analysis))

    # Step 4: Check if repair needed
    if analysis.recommendation == 0:
        print(f'  {ok("No repair needed. Syscon appears healthy.")}')
        if input(f'  {info("Save a copy anyway?")} (y/n): ').strip().lower() == 'y':
            out_dir = os.path.dirname(syscon_path)
            base = os.path.splitext(os.path.basename(syscon_path))[0]
            out_path = os.path.join(out_dir, f'{base}_copy.bin')
            with open(out_path, 'wb') as f:
                f.write(syscon_data)
            print(f'  {ok("Saved:")} {value(out_path)}')
        return

    # Step 5: User confirms or changes repair level
    print()
    print(f'  {info("Recommended repair level:")} {value(str(analysis.recommendation))} — {REPAIR_LEVELS.get(analysis.recommendation, "?")}')

    ans = input(f'  {info("Apply recommended repair?")} (y/n/c=change level): ').strip().lower()
    level = analysis.recommendation

    if ans == 'c':
        print()
        print(f'  {info("Available levels:")}')
        for lv, desc in REPAIR_LEVELS.items():
            if lv > 0:
                print(f'    [{lv}] {desc}')
        lv_in = input(f'  {info("Choose level")} (1-4): ').strip()
        try:
            level = int(lv_in)
            if level < 1 or level > 4:
                print(f'  {fail("Invalid level, using recommended.")}')
                level = analysis.recommendation
        except ValueError:
            print(f'  {warn("Invalid input, using recommended level.")}')
            level = analysis.recommendation
    elif ans != 'y':
        print(f'  {dim("Repair cancelled.")}')
        return

    # Step 6: If level 4 (full repair) → donor selection with confirmation
    if level == 4:
        from ps4nor.v2_features.syscon_regen import SysconDonorDB
        db = SysconDonorDB(SYSCON_DONORS_DIR)
        donors = db.scan()
        if not donors:
            print(f'  {fail("No syscon donors found in syscon_donors/.")}')
            print(f'  {warn("Cannot perform full repair without donors.")}')
            if input(f'  {info("Fall back to heavy repair (level 3)?")} (y/n): ').strip().lower() == 'y':
                level = 3
            else:
                return

        ranked = db.match(nor_data or syscon_data)
        if not ranked:
            print(f'  {fail("No compatible donor found.")}')
            print(f'  {warn("Best match score too low — no suitable donor.")}')
            if input(f'  {info("Continue anyway with level 3?")} (y/n): ').strip().lower() == 'y':
                level = 3
            else:
                return

        # Show top 3 donors
        print()
        print(f'  {info("Top donors (ranked):")}')
        for i, d in enumerate(ranked[:3], 1):
            score_str = value(str(d.match_score)) if d.match_score >= 0 else dim('NA')
            warning = '  {warn("WARNING: Low match!")}' if d.match_score < 50 else ''
            print(f'    {ok(f"[{i}]")} {head(d.filename)}  {dim(f"({d.fw_count} FW recs, score={score_str}, {d.match_reason})")}')

        if len(ranked) > 3:
            print(f'    {dim(f"... and {len(ranked) - 3} more")}')

        print()
        sel = input(f'  {info("Choose donor")} (1-{min(len(ranked), 3)}, or 0 to cancel): ').strip()
        try:
            s = int(sel)
            if s == 0:
                print(f'  {dim("Repair cancelled.")}')
                return
            chosen = ranked[s - 1]
        except (ValueError, IndexError):
            print(f'  {fail("Invalid, using top donor.")}')
            chosen = ranked[0]

        print(f'  Selected: {head(chosen.filename)} (score={value(str(chosen.match_score))})')
        if chosen.match_score < 50:
            confirm = input(f'  {warn("This donor may not match well. Continue?")} (y/n): ').strip().lower()
            if confirm != 'y':
                print(f'  {dim("Repair cancelled.")}')
                return

    # Step 7: Execute repair
    print()
    print(f'  {dim(f"Applying level {level} repair...")}')

    from ps4nor.v2_features.syscon_regen import syscon_light_repair, syscon_auto_repair, syscon_rebuild_from_nor
    result = None
    report = ''

    if level == 1:
        result, report = syscon_light_repair(syscon_data)
    elif level == 2:
        from ps4nor.v2_features.syscon_regen import wee_rebuild
        result, report = wee_rebuild(syscon_data)
    elif level == 3:
        result, report, _ = syscon_auto_repair(syscon_data, nor_data)
        # auto_repair returns (bytes, str, level)
        result, report = result, report
    elif level == 4:
        # Full repair with selected donor
        from ps4nor.v2_features.syscon_regen import syscon_regenerate
        try:
            with open(chosen.filepath, 'rb') as f:
                donor_data = f.read()
        except Exception as e:
            print(f'  {fail(f"Error reading donor: {e}")}')
            return

        result, report = syscon_regenerate(nor_data or syscon_data, donor_data, method='auto')

    if result is None:
        print(f'  {fail(f"Repair failed: {report}")}')
        return

    # Step 8: Show result
    print()
    for line in report.split('\n'):
        print(f'  {line}')

    # Final analysis
    print()
    from ps4nor.v2_features.syscon_analyzer import analyze_syscon
    final = analyze_syscon(result, nor_data)
    print(f'  Final severity: {value(final.severity)}')

    # Step 9: Save
    out_dir = os.path.dirname(syscon_path)
    base = os.path.splitext(os.path.basename(syscon_path))[0]
    out_path = os.path.join(out_dir, f'{base}_repaired.bin')
    with open(out_path, 'wb') as f:
        f.write(result)
    print(f'  {ok("Saved:")} {value(out_path)}')
    print(f'  {ok("Done.")}')


# ======================================================================
# MENU
# ======================================================================

def main_menu():
    global _current_path
    while True:
        print()
        print(hr(color='cyan'))
        print(f'  {brand("PS4 NOR VALIDATOR PRO v" + __version__ + " - ADVANCED FEATURES")}')
        print(f'  {dim("by ISLAM JAMEL")}')
        print(hr(color='cyan'))
        dump_name = os.path.basename(_current_path) if _current_path else "(none)"
        print(f'  {info("Dump:")} {value(dump_name)}')
        print()
        print(f'  {warn("[!] ALWAYS keep your original files safe!")}')
        print()
        print(f'  {info("L.")} Load NOR dump')
        print()
        print(f'  {info("R.")} Smart Auto-Repair v2')
        print(f'  {info("E.")} Smart Auto-Repair v2.1  (Hybrid: FWS+Donor)')
        print()
        print(f'  {info("H.")} HDD Metadata Analyzer')
        print(f'  {info("D.")} Analyze Damage')
        print(f'  {info("G.")} Guided Interactive Repair')
        print(f'  {info("N.")} NVS Regeneration  (3 methods)')
        print(f'  {info("C.")} Syscon Regeneration  (donor/WeeTools rebuild)')
        print(f'  {info("V.")} Downgrade Assistant  (slot switch + EAP)')
        print()
        print(f'  {info("S.")} Smart Donor Match')
        print(f'  {info("K.")} Donor List')
        print(f'  {info("B.")} Rebuild Donor/Blob Database')
        print()
        print(f'  {title("=== AND MORE ===")}')
        print(f'   4. Extract All Console Keys')
        print(f'   5. Extract HDD XTS Keys')
        print()
        print(f'  {info("0.")} Exit')
        print()
        choice = input('Select: ').strip().lower()

        if choice == '4':
            extract_all_keys()
        elif choice == '5':
            extract_hdd_keys()
        elif choice in ('s', '9'):
            donor_match()
        elif choice in ('k', '10'):
            donor_list()
        elif choice == 'h':
            hdd_analysis()
        elif choice == 'r':
            smart_repair()
        elif choice == 'e':
            hybrid_repair()
        elif choice == 'd':
            analyze_damage()
        elif choice == 'g':
            guided_repair()
        elif choice == 'n':
            nvs_regeneration()
        elif choice == 'c':
            syscon_rebuild()
        elif choice == 'v':
            downgrade_assistant()
        elif choice == 'l':
            _current_path = None
            _load_dump()
        elif choice == 'b':
            rebuild_db()
        elif choice == '0':
            print('Goodbye!')
            break
        else:
            print('Invalid choice.')

        _pause()


# ======================================================================
# CLI MODE
# ======================================================================

def cli_mode(args: list):
    if len(args) < 2:
        print(f'  {info("Usage:")} python main_v2.py <dump> [command]')
        print(f'  {dim("Commands: keys, hdd, donors, damage, syscon, slb2")}')
        return

    dump_path = args[0]
    if not os.path.exists(dump_path):
        print(f'  {fail("Error:")} {warn(f"File not found: {dump_path}")}')
        return

    with open(dump_path, 'rb') as f:
        nor_data = f.read()
    print(f'  {ok("Loaded:")} {value(dump_path)} {dim(f"({len(nor_data):,} bytes)")}')

    cmd = args[1].lower() if len(args) > 1 else 'all'

    if cmd in ('syscon', 'all'):
        syscon = nor_data[0x60000:0x60000 + 0x80000] if len(nor_data) >= 0xE0000 else nor_data[-0x80000:]
        if syscon:
            print(format_syscon_report(syscon))

    if cmd in ('keys', 'hdd', 'all'):
        syscon = nor_data[0x60000:0x60000 + 0x80000] if len(nor_data) >= 0xE0000 else None
        extractor = ConsoleKeysExtractor(nor_data, syscon)
        keys = extractor.extract_all()
        if cmd in ('keys', 'all'):
            print(extractor.to_text_report())
        elif cmd == 'hdd':
            hdd = keys.get('hdd_keys', {})
            print(f'  {info("HDD Data Key:")}  {value(hdd.get("data_key_hex", "N/A"))}')
            print(f'  {info("HDD Tweak Key:")} {value(hdd.get("tweak_key_hex", "N/A"))}')

    if cmd == 'hdd':
        from ps4nor.v2_features.hdd_analyzer import analyze_hdd_metadata, format_hdd_report
        a = analyze_hdd_metadata(nor_data)
        r = format_hdd_report(a).replace('\u2260', '!=')
        print()
        print(r)

    if cmd in ('slb2', 'all'):
        for name, off in [('EMC_IPL_A', 0x200000), ('EMC_IPL_B', 0x2F0000),
                          ('EAP_KBL', 0x1C000), ('Torus', 0x144000)]:
            if off + 0x40 <= len(nor_data) and nor_data[off:off + 4] == b'SLB2':
                try:
                    rb = SLB2Rebuilder.parse(nor_data[off:off + 0x10000])
                    print(f'\n--- SLB2 @ {hex(off)} ({name}) ---')
                    print(rb.report())
                except Exception as e:
                    print(f'SLB2 @ {hex(off)}: {e}')

    if cmd in ('donors', 'all'):
        if os.path.isdir(DONORS_DIR):
            matcher = SmartDonorMatcher(DONORS_DIR)
            print(f'\n  {info("Donors:")} {value(str(matcher.donor_count))}')


# ======================================================================
# ENTRY
# ======================================================================

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] != '-i':
        cli_mode(sys.argv[1:])
    else:
        if len(sys.argv) > 2:
            _current_path = sys.argv[2]
            _load_dump(sys.argv[2])
        main_menu()
