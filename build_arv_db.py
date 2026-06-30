"""
build_arv_db.py - Build ARV→FW mapping database from paired NOR+Syscon dumps.

Scans NOR dumps from D:\2, matches them with syscon pairs, extracts:
  - From NOR: FW version, Board ID, MAC, Serial, CORE_SWCH, EAP_KBL MD5
  - From syscon (via DONOR_MD5_MAP): chip, ARV, FW records

Outputs:
  - arv_db.csv       — all data in spreadsheet format
  - arv_fw_map.py    — Python dict for direct import
"""

import os, sys, hashlib, re, struct, csv

# ── Paths ──────────────────────────────────────────────────────────────
ROOT = r'C:\Users\ENG OMAR\Downloads\github.com-BetterWayElectronics-ps4-nor-validator_-_2024-08-03_05-31-02 (1)\PS4_NOR_Validator_Pro_v2'
sys.path.insert(0, ROOT)

DONORS_DIR = os.path.join(ROOT, 'syscon_donors')
ARV_MAP_PATH = os.path.join(ROOT, 'ps4nor', 'utils', 'arv_map.py')
OUT_CSV = os.path.join(ROOT, 'arv_db.csv')
OUT_PY = os.path.join(ROOT, 'arv_fw_map.py')

# Use real FW detection from codebase
from ps4nor.utils.helpers import detect_fw_version, detect_active_slot

# NOR directories to scan
NOR_DIRS = [
    r'D:\2\dump nor',
    r'D:\2\UserData',
    r'D:\2\UserData\New folder',
    r'D:\2\UserData\New folder (2)',
    r'D:\2\115s',
    r'D:\2\blooooo',
    r'D:\2\ISLAM\dump nor',
    r'D:\2\ISLAM\BwE validator',
    r'D:\2\ISLAM\ps4-wee-tools-pro-v1.0.2',
    r'D:\2\ISLAM\PS4\wee99',
    r'D:\2\ISLAM\207\BwE_PS4_NOR_Validator 2.0.7',
    r'D:\2\New folder (3)',
    r'D:\2\NeoProgrammer V2.2.0.10\Dump',
]
SYSCON_DIRS = [
    r'D:\2\ISLAM\dump sys',
    r'D:\2\UserData',
    r'D:\2\115s',
    r'D:\2\blooooo',
    r'D:\2\New folder (3)',
    r'D:\2\ISLAM',
]
# ── NOR extraction constants ───────────────────────────────────────────
BOARD_ID_OFF = 0x1C4000
BOARD_ID_SZ = 8
MAC_OFF = 0x1C4021
MAC_SZ = 6
CORE_SWCH = 0x201000
CORE_SWCH_SZ = 16
UART_OFF = 0x1C931F

# ── Helpers ────────────────────────────────────────────────────────────
def md5(data):
    return hashlib.md5(data).hexdigest().lower()

def load_donor_map():
    """Load DONOR_MD5_MAP from arv_map.py"""
    ns = {}
    with open(ARV_MAP_PATH) as f:
        exec(compile(f.read(), ARV_MAP_PATH, 'exec'), ns)
    return ns.get('DONOR_MD5_MAP', {})



def get_core_swch(data):
    if len(data) < CORE_SWCH + 16:
        return None
    return data[CORE_SWCH:CORE_SWCH + 16].hex()

def get_board_id(data):
    if len(data) < BOARD_ID_OFF + BOARD_ID_SZ:
        return None
    b = data[BOARD_ID_OFF:BOARD_ID_OFF + BOARD_ID_SZ]
    return ':'.join(f'{x:02X}' for x in b)

def get_mac(data):
    if len(data) < MAC_OFF + MAC_SZ:
        return None
    m = data[MAC_OFF:MAC_OFF + MAC_SZ]
    # Skip invalid
    if all(x == 0xFF for x in m) or all(x == 0x00 for x in m):
        return None
    return ':'.join(f'{x:02X}' for x in m)

def get_serial(data):
    for offset in [0x1CA000, 0x0A4000]:
        if offset + 0x1000 > len(data):
            continue
        chunk = data[offset:offset + 0x1000]
        m = re.search(rb'\d{10,16}', chunk)
        if m:
            return m.group(0).decode('ascii')
    return None

def get_uart_status(data):
    if len(data) <= UART_OFF:
        return None
    return data[UART_OFF]

def index_syscons():
    """Build dict: base_name -> list of {file, path, md5, size}"""
    sc_idx = {}
    for sd in SYSCON_DIRS:
        if not os.path.isdir(sd):
            continue
        for f in os.listdir(sd):
            if not f.lower().endswith('.bin'):
                continue
            fp = os.path.join(sd, f)
            sz = os.path.getsize(fp)
            if sz not in (524288, 262144):
                continue
            data = open(fp, 'rb').read()
            m = md5(data)
            base = f.rsplit('-', 1)[0] if '-0' in f else f.replace('.bin', '').replace('.BIN', '')
            base = base.upper()
            if base not in sc_idx:
                sc_idx[base] = {}
            sc_idx[base][m] = {'file': f, 'path': fp, 'size': sz, 'md5': m}
    return sc_idx

def nor_base_name(fname):
    """Extract base name from NOR filename for matching with syscon"""
    name = fname
    if name.upper().endswith('.BIN'):
        name = name[:-4]
    # Handle special suffixes like _slot_switch_3, _sb-coreos-uart-patched_1_00 etc.
    for skip in ['_slot_switch', '_sb-coreos-uart', '_patch_s0', '_patch_sb', '_080B',
                 '_wifi_patch', '_emc_ipl', '_eap_kbl', '_fw_patch']:
        if skip in name.upper():
            return None  # Skip patched/modified NOR dumps
    # Skip obvious WeeTools outputs
    if '_rebuild' in name.lower() or '_clean' in name.lower() or 'good' in name.lower() or 'fixed' in name.lower():
        return None
    return name.upper()

# ── Main ───────────────────────────────────────────────────────────────
def main():
    print('Loading DONOR_MD5_MAP...')
    donor_map = load_donor_map()
    print(f'  {len(donor_map)} entries')

    print('Indexing syscon files...')
    sc_idx = index_syscons()
    total_sc = sum(len(v) for v in sc_idx.values())
    print(f'  {len(sc_idx)} base names, {total_sc} files')

    print('Scanning NOR directories...')
    results = []
    nor_count = 0
    paired = 0
    matched_donor = 0

    for nd in NOR_DIRS:
        if not os.path.isdir(nd):
            continue
        for f in sorted(os.listdir(nd)):
            if not (f.lower().endswith('.bin')):
                continue
            fp = os.path.join(nd, f)
            sz = os.path.getsize(fp)
            if sz != 33554432:
                continue  # Not a raw NOR dump

            base = nor_base_name(f)
            if base is None:
                continue

            nor_count += 1

            # Look for matching syscon by base name
            if base not in sc_idx:
                continue

            try:
                data = open(fp, 'rb').read()
            except:
                continue

            nor_md5 = md5(data)

            # Use real FW detection from codebase
            fw_ver = detect_fw_version(data) or 'Unknown'

            active_slot = detect_active_slot(data)
            board_id = get_board_id(data)
            mac_addr = get_mac(data)
            serial = get_serial(data)
            core_swch = get_core_swch(data)
            uart = get_uart_status(data)

            for sc_md5, sc_info in sc_idx[base].items():
                # Check if this syscon is in DONOR_MD5_MAP
                if sc_md5 in donor_map:
                    dm = donor_map[sc_md5]
                    matched_donor += 1
                else:
                    dm = {'chip': 'Unknown', 'arv': -1, 'fw_records': -1}

                results.append({
                    'nor_file': f,
                    'nor_dir': os.path.basename(nd),
                    'nor_md5': nor_md5,
                    'fw_version': fw_ver,
                    'active_slot': active_slot,
                    'board_id': board_id or '',
                    'mac': mac_addr or '',
                    'serial': serial or '',
                    'core_swch': core_swch or '',
                    'uart_byte': f'0x{uart:02X}' if uart is not None else '',
                    'syscon_file': sc_info.get('file', ''),
                    'syscon_size': sc_info.get('size', 0),
                    'syscon_md5': sc_md5,
                    'chip': dm.get('chip', 'Unknown'),
                    'arv': dm.get('arv', -1),
                    'fw_records': dm.get('fw_records', -1),
                    'donor_source': dm.get('file', ''),
                })
                paired += 1

    print(f'\nNOR dumps scanned: {nor_count}')
    print(f'Paired (NOR+syscon): {paired}')
    print(f'Matched to donors: {matched_donor}')
    print(f'Results ready: {len(results)}')

    if not results:
        print('ERROR: No results! Check paths.')
        return

    # Write CSV
    fields = ['nor_file', 'nor_dir', 'nor_md5', 'fw_version',
              'active_slot', 'board_id', 'mac', 'serial', 'core_swch', 'uart_byte',
              'syscon_file', 'syscon_size', 'syscon_md5', 'chip', 'arv',
              'fw_records', 'donor_source']

    with open(OUT_CSV, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(results)
    print(f'\nCSV saved: {OUT_CSV}')

    # Build ARV→FW mapping (skip invalid FW)
    fw_map = {}
    for r in results:
        fw = r['fw_version']
        if r['arv'] < 0 or fw in ('Unknown', '0.00'):
            continue
        key = (r['chip'], r['arv'])
        if key not in fw_map:
            fw_map[key] = set()
        fw_map[key].add(fw)

    # Also build NOR_MD5 → FW reverse mapping
    nor_fw_map = {}
    for r in results:
        nor_fw_map[r['nor_md5']] = r['fw_version']

    py_lines = []
    py_lines.append('#!/usr/bin/env python3')
    py_lines.append('"""')
    py_lines.append('ARV→FW Version Mapping Database')
    py_lines.append(f'Auto-generated by build_arv_db.py from {len(results)} paired dumps.')
    py_lines.append('Maps (chip, arv) tuples to known FW versions.')
    py_lines.append('"""')
    py_lines.append('')
    py_lines.append('# (chip, arv) -> sorted list of known FW versions')
    py_lines.append('ARV_FW_MAP = {')
    for (chip, arv), fws in sorted(fw_map.items()):
        fw_list = sorted(fws)
        py_lines.append(f"    ('{chip}', {arv}): {fw_list},")
    py_lines.append('}')
    py_lines.append('')
    py_lines.append('')
    py_lines.append('# NOR MD5 -> FW version (for quick lookup)')
    py_lines.append('NOR_FW_MAP = {')
    for m, fw in sorted(nor_fw_map.items()):
        py_lines.append(f"    '{m}': '{fw}',")
    py_lines.append('}')

    with open(OUT_PY, 'w', encoding='utf-8') as f:
        f.write('\n'.join(py_lines))
    print(f'FW map saved: {OUT_PY}')

    # Quick stats
    print()
    print('== Summary ==')
    chips = set(r['chip'] for r in results)
    print(f'Chips found: {", ".join(sorted(chips))}')
    print(f'Unique (chip, arv) pairs: {len(fw_map)}')
    valid_fws = set(r['fw_version'] for r in results if r['fw_version'] not in ('Unknown', '0.00'))
    print(f'Valid FW versions: {len(valid_fws)} ({", ".join(sorted(valid_fws))})')

    # Show distribution by chip/arv
    print()
    print('-- Distribution by Chip + ARV --')
    for (chip, arv), fws in sorted(fw_map.items()):
        fw_str = ', '.join(sorted(fws)[:5])
        if len(fws) > 5:
            fw_str += f' ... (+{len(fws) - 5} more)'
        print(f'  {chip} ARV={arv:>3}: {fw_str}')

if __name__ == '__main__':
    main()
