#!/usr/bin/env python3
"""
Build ARV Database from deduplicated syscon dumps.
Strategy: Extract what we CAN determine reliably:
  1. MD5 hash
  2. File size (256KB vs 512KB)
  3. SNVS FW record count (proxy for FW version)
  4. eFuse ARV from PRE0 entries (type 0x0C) — best attempt
  5. Detect chip type from firmware header patterns
Outputs: arv_map.py in ps4nor/utils/
"""
import sys, os, hashlib
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SYSCON_DIR = os.path.join(ROOT, 'syscon_donors')
OUTPUT_DIR = os.path.join(ROOT, 'ps4nor', 'utils')

SNVS_OFF = 0x60000
AREA_SIZE = 0x1800
AREA_COUNT = 9
ENTRY_SIZE = 16
FLAT_SIZE = 0x400

FW_TYPES = (0x08, 0x09, 0x0A, 0x0B)

def area_start(n):
    return SNVS_OFF + 0x800 + n * AREA_SIZE

def iter_entries(data):
    for area_n in range(AREA_COUNT):
        astart = area_start(area_n)
        for i in range(FLAT_SIZE, AREA_SIZE, ENTRY_SIZE):
            pos = astart + i
            if pos + ENTRY_SIZE > len(data):
                break
            raw = data[pos:pos + ENTRY_SIZE]
            if raw[0] == 0xA5 and raw[7] == 0xC3:
                typ = raw[1] | (raw[2] << 8)
                ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                yield (pos, typ, ctr, bytes(raw[8:16]))

def count_fw_records(data):
    """Count FW update records (type 0x08-0x0B quadruplets)."""
    entries = []
    for pos, typ, ctr, d in iter_entries(data):
        entries.append((pos, typ, ctr, d))
    records = 0
    i = 0
    while i < len(entries):
        if entries[i][1] == 0x08:
            if (i + 3 < len(entries) and
                entries[i+1][1] == 0x09 and
                entries[i+2][1] == 0x0A and
                entries[i+3][1] == 0x0B and
                entries[i+1][0] - entries[i][0] == ENTRY_SIZE and
                entries[i+2][0] - entries[i+1][0] == ENTRY_SIZE and
                entries[i+3][0] - entries[i+2][0] == ENTRY_SIZE):
                records += 1
                i += 4
                continue
        i += 1
    return records

def extract_efuse_arv(data):
    """
    Extract anti-rollback version from SNVS eFuse entries.
    Real ARV is stored in PRE0 (type 0x0C) entries.
    The last written PRE0 (highest addr in the 9 areas) contains the current ARV.
    """
    best_pre0 = None
    for pos, typ, ctr, d in iter_entries(data):
        if typ == 0x0C:
            if best_pre0 is None or pos > best_pre0[0]:
                best_pre0 = (pos, typ, ctr, d)
    if best_pre0:
        return best_pre0[3][0]  # first byte of data
    return -1

def detect_chip(data):
    """
    Detect syscon chip type from firmware patterns.
    Only 512KB dumps have full firmware to analyze.
    The chip firmware has unique patterns at known offsets.
    """
    if len(data) < 0x100:
        return 'Unknown'
    
    # Check firmware area for chip-specific patterns
    # CXD90025G: early FAT, different bootloader
    # CXD90044G: late FAT / early SLIM
    # CXD90068G: late SLIM / PRO
    
    # Strategy: check the number of FW records + total SNVS entries
    # Different chips have different SNVS area layouts
    
    # Count total entries
    total_entries = sum(1 for _ in iter_entries(data))
    fw_records = count_fw_records(data)
    
    # Rough classification based on SNVS structure
    # CXD90025G: smaller firmware area, fewer total entries
    # CXD90044G: medium
    # CXD90068G: largest, most entries
    
    if total_entries < 500:
        return 'CXD90025G'
    elif total_entries < 1500:
        return 'CXD90044G'
    else:
        return 'CXD90068G'

def md5_file(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def main():
    files = sorted(os.listdir(SYSCON_DIR))
    files = [f for f in files if f.endswith('.bin') and os.path.isfile(os.path.join(SYSCON_DIR, f))]
    
    db = {}
    
    print(f"Scanning {len(files)} syscon files...")
    
    for name in files:
        fpath = os.path.join(SYSCON_DIR, name)
        size = os.path.getsize(fpath)
        if size not in (0x40000, 0x80000):
            print(f"  SKIP (size {size}): {name}")
            continue
        
        md5 = md5_file(fpath)
        if md5 in db:
            db[md5]['sources'].append(name)
            continue
        
        with open(fpath, 'rb') as f:
            data = f.read()
        
        fw_records = count_fw_records(data)
        arv = extract_efuse_arv(data)
        chip = detect_chip(data)
        
        db[md5] = {
            'file': name,
            'size': size,
            'fw_records': fw_records,
            'arv': arv,
            'chip': chip,
            'sources': [name],
        }
    
    # === ANALYSIS ===
    print(f"\n{'='*60}")
    print(f"UNIQUE SYSCON DUMPS: {len(db)}")
    
    # Group by chip
    chip_groups = defaultdict(list)
    for md5, entry in db.items():
        chip_groups[entry['chip']].append(entry)
    
    print(f"\n--- Chip Distribution ---")
    for chip in sorted(chip_groups.keys()):
        print(f"  {chip}: {len(chip_groups[chip])} files")
    
    # Group by ARV
    arv_groups = defaultdict(list)
    for md5, entry in db.items():
        arv_groups[entry['arv']].append(entry)
    
    print(f"\n--- ARV Distribution ---")
    for arv in sorted(arv_groups.keys()):
        group = arv_groups[arv]
        chips = set(e['chip'] for e in group)
        fw_recs = [e['fw_records'] for e in group]
        min_fw = min(fw_recs)
        max_fw = max(fw_recs)
        samples = ', '.join(e['file'] for e in group[:3])
        print(f"  ARV {arv:>3d}: {len(group):>3d} files, chips={chips}, FW_records={min_fw}-{max_fw}, ex: {samples}")
    
    # Group by chip + FW record range
    print(f"\n--- Chip / FW Record Groups ---")
    for chip in sorted(chip_groups.keys()):
        entries = chip_groups[chip]
        rec_groups = defaultdict(list)
        for e in entries:
            rec_groups[e['fw_records']].append(e)
        print(f"\n  [{chip}] ({len(entries)} files, FW record ranges:)")
        for rec in sorted(rec_groups.keys()):
            group = rec_groups[rec]
            print(f"    {rec:>4d} records: {len(group):>3d} files")
    
    # === GENERATE arv_map.py ===
    print(f"\n{'='*60}")
    print("Generating arv_map.py...")
    
    lines = []
    lines.append('#!/usr/bin/env python3')
    lines.append('"""')
    lines.append('ARV (Anti-Rollback Version) Database')
    lines.append('Auto-generated from syscon donor analysis.')
    lines.append(f'Total unique dumps: {len(db)}')
    lines.append('"""')
    lines.append('')
    lines.append('# DONOR MD5 MAP — full list of deduplicated syscon donors')
    lines.append('DONOR_MD5_MAP = {')
    
    for md5 in sorted(db.keys()):
        e = db[md5]
        lines.append("    '{0}': {{".format(md5))
        lines.append("        'file': '{0}',".format(e['file']))
        lines.append("        'size': {0},".format(e['size']))
        lines.append("        'chip': '{0}',".format(e['chip']))
        lines.append("        'arv': {0},".format(e['arv']))
        lines.append("        'fw_records': {0},".format(e['fw_records']))
        lines.append("        'sources': {0},".format(e['sources']))
        lines.append("    }},")
    
    lines.append('}')
    lines.append('')
    lines.append('')
    lines.append('# ARV → FW record range (per chip)')
    lines.append('ARV_MAP = {')
    
    for chip in sorted(chip_groups.keys()):
        chip_arvs = defaultdict(list)
        for e in chip_groups[chip]:
            chip_arvs[e['arv']].append(e)
        
        for arv in sorted(chip_arvs.keys()):
            group = chip_arvs[arv]
            fw_recs = [e['fw_records'] for e in group]
            min_rec = min(fw_recs)
            max_rec = max(fw_recs)
            lines.append("    ('{0}', {1}): {{'fw_records': ({2}, {3}), 'count': {4}}},".format(
                chip, arv, min_rec, max_rec, len(group)))
    
    lines.append('}')
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    outpath = os.path.join(OUTPUT_DIR, 'arv_map.py')
    with open(outpath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    
    print(f"Wrote {outpath}")
    print(f"\nDone!")

if __name__ == '__main__':
    main()
