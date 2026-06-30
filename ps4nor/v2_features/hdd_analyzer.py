"""
HDD Metadata Analyzer — NVS structure analysis & repair.

PS4 NVS area (0x1C4000–0x1D0000):
  OFF_HDD_META    = 0x1000 (0x1C5000): HDD metadata block (primary)
  OFF_SERIAL      = 0x4000 (0x1C8000): Console serial number at +0x20
  OFF_CID_CRC     = 0x5000 (0x1C9000): CID CRC region
  OFF_CID         = 0x6000 (0x1CA000): CID region
  OFF_CB          = 0x7000 (0x1CB000): CB region (0xFF)
  OFF_CID_CRC_MIR = 0x8000 (0x1CC000): Mirror of CID CRC
  OFF_CID_MIR     = 0x9000 (0x1CD000): Mirror of CID
  OFF_HDD_META_DUP = 0xA000 (0x1CE000): HDD metadata (mirror)

HDD EAP key at 0x1C9200 (wrapped key blob, magic \xE5\xE5\xE5\x01 at 0x1C91FC).
"""
from typing import List, Optional, Dict, Tuple
import os
import re
from math import log2
from ..utils.colors import C, ok, fail, warn, info, title, brand, dim, value, status_bool
from ..utils.nor_defs import NVS_IDENTITY_RANGES

# NVS constants (from nvs_generator.py)
NVS_START = 0x1C4000
NVS_END = 0x1D0000
NVS_SIZE = NVS_END - NVS_START

# Sub-region offsets (relative to NVS_START)
OFF_HDD_META    = 0x1000  # 0x1C5000
OFF_FLAGS1      = 0x3000  # 0x1C7000
OFF_SERIAL      = 0x4000  # 0x1C8000
OFF_CID_CRC     = 0x5000  # 0x1C9000
OFF_CID         = 0x6000  # 0x1CA000
OFF_CB          = 0x7000  # 0x1CB000
OFF_CID_CRC_MIR = 0x8000  # 0x1CC000
OFF_CID_MIR     = 0x9000  # 0x1CD000
OFF_HDD_META_DUP = 0xA000  # 0x1CE000

# Absolute offsets
HDD_META_1 = NVS_START + OFF_HDD_META     # 0x1C5000
HDD_META_2 = NVS_START + OFF_HDD_META_DUP  # 0x1CE000
HDD_META_SIZE = 0x1000

# EAP key offsets
HDD_KEY_MAGIC = 0x1C91FC  # Expected: \xE5\xE5\xE5\x01
HDD_KEY_BLOB = 0x1C9200   # wrapped key blob
HDD_KEY_BACKUP_MAGIC = 0x1CC1FC  # Backup at +0x3000
HDD_KEY_BACKUP_BLOB = 0x1CC200
EAP_KEY_SIZE = 0x60       # default 96 bytes — some FAT models use 0x40


def detect_eap_key_size(nor_data: bytes) -> int:
    """Detect EAP key blob size: 0x40 (FAT CUH-10xx) or 0x60 (others).
    Checks if bytes at 0x40-0x5F in the key blob are all 0x00/0xFF (padding)."""
    primary = nor_data[HDD_KEY_BLOB:HDD_KEY_BLOB + 0x60] if len(nor_data) >= HDD_KEY_BLOB + 0x60 else b''
    backup = nor_data[HDD_KEY_BACKUP_BLOB:HDD_KEY_BACKUP_BLOB + 0x60] if len(nor_data) >= HDD_KEY_BACKUP_BLOB + 0x60 else b''
    for blob in [primary, backup]:
        if len(blob) >= 0x60:
            tail = blob[0x40:0x60]
            if any(b not in (0, 0xFF) for b in tail):
                return 0x60
    return 0x40

# HDD info string table (inside CID CRC region)
HDD_INFO_OFF = 0x1C9C00   # Primary HDD model+serial
HDD_INFO_MIRROR = 0x1CCC00  # Mirror copy
HDD_INFO_MODEL_LEN = 0x30  # 48 bytes model
HDD_INFO_SERIAL_LEN = 0x10  # 16 bytes serial

# NVS region labels
NVS_REGIONS = {
    OFF_HDD_META: 'HDD Metadata',
    OFF_FLAGS1: 'Flags1',
    OFF_SERIAL: 'Serial Number',
    OFF_CID_CRC: 'CID CRC',
    OFF_CID: 'CID',
    OFF_CB: 'CB (0xFF)',
    OFF_CID_CRC_MIR: 'CID CRC (mirror)',
    OFF_CID_MIR: 'CID (mirror)',
    OFF_HDD_META_DUP: 'HDD Metadata (mirror)',
}


def _extract_hdd_info(data: bytes, offset: int) -> Dict:
    """Extract HDD model + serial from info table at offset.
    Format: 0x30 bytes model (ASCII, space/null padded) + 0x10 bytes serial + terminator.
    """
    result = {'model': None, 'serial': None, 'clean': False, 'has_data': False}
    if offset + 0x40 > len(data):
        return result
    raw = data[offset:offset + 0x40]
    # Check if any meaningful data exists
    if sum(1 for b in raw[:0x30] if b not in (0, 0xFF)) < 4:
        return result
    result['has_data'] = True
    # Extract model (ASCII chars up to 0x00 or control char, trim spaces)
    model_bytes = []
    for b in raw[:HDD_INFO_MODEL_LEN]:
        if b == 0:
            break
        if 32 <= b < 127:
            model_bytes.append(b)
        elif b == 0x20:
            model_bytes.append(b)
    result['model'] = bytes(model_bytes).decode('ascii', errors='ignore').strip()
    # Extract serial
    serial_bytes = []
    for b in raw[HDD_INFO_MODEL_LEN:HDD_INFO_MODEL_LEN + HDD_INFO_SERIAL_LEN]:
        if b == 0:
            break
        if 32 <= b < 127:
            serial_bytes.append(b)
    result['serial'] = bytes(serial_bytes).decode('ascii', errors='ignore').strip()
    # Clean check: no control chars in the full 0x40 block
    has_ctrl = any(0 < b < 0x20 for b in raw[:0x3E])
    result['clean'] = not has_ctrl
    return result


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    for c in counts:
        if c:
            p = c / len(data)
            ent -= p * log2(p)
    return ent


def _extract_strings(data: bytes, min_len: int = 3) -> List[str]:
    result = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            j = i
            while j < len(data) and 32 <= data[j] < 127:
                j += 1
            s = data[i:j].decode('ascii', errors='ignore')
            if len(s) >= min_len:
                result.append(s)
            i = j
        else:
            i += 1
    return result


def analyze_hdd_metadata(nor_data: bytes) -> Dict:
    """
    Full analysis of NVS/HDD metadata region in NOR dump.

    Returns:
        {
            'nvs_offsets': {...}  — per-sub-region analysis,
            'healthy': bool,
            'mirror_synced': bool,   // HDD metadata primary == mirror
            'warnings': [str],
            'recommendations': [str],
            'console_serial': str,   // from 0x1C8020
            'keys_valid': bool,      // EAP HDD wrapped key present
            'nvs_subregions': {int: {'name':str, 'healthy':bool}},
        }
    """
    result = {
        'nvs_offsets': {},
        'healthy': False,
        'mirror_synced': False,
        'warnings': [],
        'notes': [],
        'recommendations': [],
        'console_serial': None,
        'keys_valid': False,
        'hdd_info_clean': False,
        'hdd_model': None,
        'hdd_serial': None,
        'keys_primary_valid': False,
        'keys_backup_valid': False,
        'keys_match': False,
        'nvs_subregions': {},
    }

    if len(nor_data) < NVS_START + NVS_SIZE:
        result['warnings'].append('NOR too small for NVS area')
        return result

    nvs = nor_data[NVS_START:NVS_START + NVS_SIZE]
    healthy_count = 0
    total_regions = 0

    for off, name in NVS_REGIONS.items():
        chunk = nvs[off:off + 0x1000]
        nz = sum(1 for b in chunk if b not in (0, 0xFF))
        ent = _entropy(chunk)
        if off == OFF_CB:
            region_healthy = nz == 0  # CB must be exactly all 0xFF
        elif off == OFF_FLAGS1:
            region_healthy = nz > 2
        else:
            region_healthy = nz > 32
        if region_healthy:
            healthy_count += 1
        total_regions += 1

        result['nvs_subregions'][off] = {
            'name': name,
            'healthy': region_healthy,
            'non_zero': nz,
            'entropy': round(ent, 2),
        }

    # Overall health: most sub-regions healthy
    result['healthy'] = healthy_count >= total_regions // 2

    # HDD metadata primary vs mirror sync check
    meta1 = nvs[OFF_HDD_META:OFF_HDD_META + 0x1000]
    meta2 = nvs[OFF_HDD_META_DUP:OFF_HDD_META_DUP + 0x1000]
    h1_healthy = sum(1 for b in meta1 if b not in (0, 0xFF)) > 32
    h2_healthy = sum(1 for b in meta2 if b not in (0, 0xFF)) > 32
    result['mirror_synced'] = meta1 == meta2

    if not result['mirror_synced'] and h1_healthy and h2_healthy:
        result['notes'].append('HDD metadata copies differ — both healthy, likely HDD change')
    elif not h1_healthy and h2_healthy:
        result['warnings'].append('HDD metadata primary (0x1C5000) corrupt')
        result['recommendations'].append('Restore primary from mirror')
    elif h1_healthy and not h2_healthy:
        result['warnings'].append('HDD metadata mirror (0x1CE000) corrupt')
        result['recommendations'].append('Restore mirror from primary')
    elif not h1_healthy and not h2_healthy:
        result['warnings'].append('Both HDD metadata copies empty/corrupt')
        result['recommendations'].append('Replace from known-good donor')

    # Check CID_CRC vs mirror
    cid_crc = nvs[OFF_CID_CRC:OFF_CID_CRC + 0x1000]
    cid_crc_mir = nvs[OFF_CID_CRC_MIR:OFF_CID_CRC_MIR + 0x1000]
    cid_crc_h1 = sum(1 for b in cid_crc if b not in (0, 0xFF)) > 32
    cid_crc_h2 = sum(1 for b in cid_crc_mir if b not in (0, 0xFF)) > 32
    if cid_crc != cid_crc_mir:
        if cid_crc_h1 and cid_crc_h2:
            result['notes'].append('CID CRC (0x1C9000) differs from mirror (0x1CC000) — both healthy')
        else:
            result['warnings'].append('CID CRC (0x1C9000) or mirror (0x1CC000) corrupt')
            result['recommendations'].append('Sync CID CRC from healthy side')

    # Check CID vs mirror
    cid = nvs[OFF_CID:OFF_CID + 0x1000]
    cid_mir = nvs[OFF_CID_MIR:OFF_CID_MIR + 0x1000]
    cid_h1 = sum(1 for b in cid if b not in (0, 0xFF)) > 32
    cid_h2 = sum(1 for b in cid_mir if b not in (0, 0xFF)) > 32
    if cid != cid_mir:
        if cid_h1 and cid_h2:
            result['notes'].append('CID (0x1CA000) differs from mirror (0x1CD000) — both healthy')
        else:
            result['warnings'].append('CID (0x1CA000) or mirror (0x1CD000) corrupt')
            result['recommendations'].append('Sync CID from healthy side')

    # Extract console serial from 0x1C8000 region
    serial_region = nor_data[NVS_START + OFF_SERIAL:NVS_START + OFF_SERIAL + 0x1000]
    strings = _extract_strings(serial_region, min_len=8)
    for s in strings:
        if re.match(r'^[A-Z0-9]{10,20}$', s) and not s.startswith('000'):
            result['console_serial'] = s
            break

    # HDD model/serial info at 0x1C9C00
    hdd_primary = _extract_hdd_info(nor_data, HDD_INFO_OFF)
    hdd_mirror = _extract_hdd_info(nor_data, HDD_INFO_MIRROR)
    result['hdd_info_primary'] = hdd_primary
    result['hdd_info_mirror'] = hdd_mirror

    if hdd_primary.get('has_data'):
        result['hdd_model'] = hdd_primary['model']
        result['hdd_serial'] = hdd_primary['serial']
        result['hdd_info_clean'] = hdd_primary['clean']
        if not hdd_primary['clean']:
            result['warnings'].append('HDD model/serial info corrupted (control chars in data)')
            result['recommendations'].append('Restore HDD info from mirror or donor')
    elif hdd_mirror.get('has_data'):
        result['hdd_model'] = hdd_mirror['model']
        result['hdd_serial'] = hdd_mirror['serial']
        result['hdd_info_clean'] = hdd_mirror['clean']
        if not hdd_mirror['clean']:
            result['warnings'].append('HDD model/serial info (mirror) corrupted')
            result['recommendations'].append('Restore HDD info from donor')
    else:
        result['hdd_info_clean'] = False
        result['warnings'].append('No HDD model/serial data found')
        result['recommendations'].append('Replace HDD info block from donor')

    if hdd_primary.get('model') and hdd_mirror.get('model'):
        if hdd_primary['model'] != hdd_mirror['model']:
            result['warnings'].append('HDD model mismatch primary vs mirror')
            result['matched'] = False

    # Check EAP HDD keys (primary + backup)
    key_ok = False
    backup_ok = False
    key_match = False
    eap_key_size = detect_eap_key_size(nor_data)

    if len(nor_data) >= HDD_KEY_BACKUP_BLOB + eap_key_size:
        threshold = 5.0 if eap_key_size < 0x60 else 6.0
        magic = nor_data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4]
        wrapped = nor_data[HDD_KEY_BLOB:HDD_KEY_BLOB + eap_key_size]
        if magic == b'\xE5\xE5\xE5\x01' and _entropy(wrapped) > threshold:
            key_ok = True
        bmagic = nor_data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4]
        bwrapped = nor_data[HDD_KEY_BACKUP_BLOB:HDD_KEY_BACKUP_BLOB + eap_key_size]
        if bmagic == b'\xE5\xE5\xE5\x01' and _entropy(bwrapped) > threshold:
            backup_ok = True
        key_match = key_ok and backup_ok and wrapped == bwrapped

        result['keys_primary_valid'] = key_ok
        result['keys_backup_valid'] = backup_ok
        result['keys_match'] = key_match

        if key_ok:
            result['keys_valid'] = True
        elif backup_ok:
            result['keys_valid'] = True
            result['warnings'].append('HDD wrapped key: primary corrupt, using backup')
        else:
            result['warnings'].append('HDD wrapped key blob missing or corrupt (both copies)')
    else:
        result['warnings'].append('NOR too small for HDD key area')

    return result


def _is_valid_eap(data, offset, eap_key_size=None):
    """Check EAP key magic + entropy at given offset.
    0x40-byte keys need lower entropy threshold (5.0) than 0x60 (6.0)."""
    if eap_key_size is None:
        eap_key_size = detect_eap_key_size(data)
    if offset + 4 + eap_key_size > len(data):
        return False
    magic = data[offset:offset + 4]
    blob = data[offset + 4:offset + 4 + eap_key_size]
    threshold = 5.0 if eap_key_size < 0x60 else 6.0
    return magic == b'\xE5\xE5\xE5\x01' and _entropy(blob) > threshold


def repair_hdd_metadata(nor_data: bytearray, donor_data: bytes = None,
                        donors_dir: str = None) -> List[str]:
    """
    Repair NVS/HDD metadata in-place:
      - Sync HDD metadata primary↔mirror
      - Sync CID_CRC primary↔mirror
      - Sync CID primary↔mirror
      - Restore EAP HDD wrapped key from backup or donor
    Returns list of repair actions performed.
    """
    actions = []

    if len(nor_data) < NVS_START + NVS_SIZE:
        actions.append('FAILED: NOR too small')
        return actions

    eap_key_size = detect_eap_key_size(bytes(nor_data))

    # HDD metadata sync
    meta1 = nor_data[HDD_META_1:HDD_META_1 + HDD_META_SIZE]
    meta2 = nor_data[HDD_META_2:HDD_META_2 + HDD_META_SIZE]
    h1 = sum(1 for b in meta1 if b not in (0, 0xFF)) > 32
    h2 = sum(1 for b in meta2 if b not in (0, 0xFF)) > 32

    if h1 and h2:
        if meta1 != meta2:
            nor_data[HDD_META_2:HDD_META_2 + HDD_META_SIZE] = meta1
            actions.append('HDD Metadata: SYNCED (primary -> mirror)')
    elif h1 and not h2:
        nor_data[HDD_META_2:HDD_META_2 + HDD_META_SIZE] = meta1
        actions.append('HDD Metadata mirror: RESTORED from primary')
    elif not h1 and h2:
        nor_data[HDD_META_1:HDD_META_1 + HDD_META_SIZE] = meta2
        actions.append('HDD Metadata primary: RESTORED from mirror')
    elif donor_data and len(donor_data) >= HDD_META_1 + HDD_META_SIZE:
        d1 = donor_data[HDD_META_1:HDD_META_1 + HDD_META_SIZE]
        d2 = donor_data[HDD_META_2:HDD_META_2 + HDD_META_SIZE]
        if sum(1 for b in d1 if b not in (0, 0xFF)) > 32:
            nor_data[HDD_META_1:HDD_META_1 + HDD_META_SIZE] = d1
            nor_data[HDD_META_2:HDD_META_2 + HDD_META_SIZE] = d2
            actions.append('HDD Metadata: REPAIRED from donor')
        else:
            actions.append('HDD Metadata: FAILED (donor also corrupt)')
    else:
        actions.append('HDD Metadata: FAILED (no source)')

    # CID CRC sync (0x1C9000 ↔ 0x1CC000)
    c1 = nor_data[0x1C9000:0x1CA000]
    c2 = nor_data[0x1CC000:0x1CD000]
    c1h = sum(1 for b in c1 if b not in (0, 0xFF)) > 32
    c2h = sum(1 for b in c2 if b not in (0, 0xFF)) > 32
    if c1h and c2h and c1 != c2:
        nor_data[0x1CC000:0x1CD000] = c1
        actions.append('CID CRC: MIRROR RESTORED from primary')
    elif c1h and not c2h:
        nor_data[0x1CC000:0x1CD000] = c1
        actions.append('CID CRC mirror: RESTORED from primary')
    elif not c1h and c2h:
        nor_data[0x1C9000:0x1CA000] = c2
        actions.append('CID CRC primary: RESTORED from mirror')

    # CID sync (0x1CA000 ↔ 0x1CD000)
    d1 = nor_data[0x1CA000:0x1CB000]
    d2 = nor_data[0x1CD000:0x1CE000]
    d1h = sum(1 for b in d1 if b not in (0, 0xFF)) > 32
    d2h = sum(1 for b in d2 if b not in (0, 0xFF)) > 32
    if d1h and d2h and d1 != d2:
        nor_data[0x1CD000:0x1CE000] = d1
        actions.append('CID: MIRROR RESTORED from primary')
    elif d1h and not d2h:
        nor_data[0x1CD000:0x1CE000] = d1
        actions.append('CID mirror: RESTORED from primary')
    elif not d1h and d2h:
        nor_data[0x1CA000:0x1CB000] = d2
        actions.append('CID primary: RESTORED from mirror')

    # HDD model/serial info at 0x1C9C00
    hdd_p = _extract_hdd_info(nor_data, HDD_INFO_OFF)
    hdd_m = _extract_hdd_info(nor_data, HDD_INFO_MIRROR)
    hdd_p_clean = hdd_p.get('clean', False) and hdd_p.get('has_data', False)
    hdd_m_clean = hdd_m.get('clean', False) and hdd_m.get('has_data', False)

    if not hdd_p_clean and hdd_m_clean:
        nor_data[HDD_INFO_OFF:HDD_INFO_OFF + 0x40] = nor_data[HDD_INFO_MIRROR:HDD_INFO_MIRROR + 0x40]
        actions.append('HDD Info: RESTORED from mirror')
    elif hdd_p_clean and not hdd_m_clean:
        nor_data[HDD_INFO_MIRROR:HDD_INFO_MIRROR + 0x40] = nor_data[HDD_INFO_OFF:HDD_INFO_OFF + 0x40]
        actions.append('HDD Info mirror: RESTORED from primary')
    elif not hdd_p_clean and not hdd_m_clean:
        restored = False
        # Try donor_data first
        if donor_data and len(donor_data) >= HDD_INFO_MIRROR + 0x40:
            d_info = _extract_hdd_info(donor_data, HDD_INFO_OFF)
            if d_info.get('clean') and d_info.get('has_data'):
                nor_data[HDD_INFO_OFF:HDD_INFO_OFF + 0x40] = donor_data[HDD_INFO_OFF:HDD_INFO_OFF + 0x40]
                nor_data[HDD_INFO_MIRROR:HDD_INFO_MIRROR + 0x40] = donor_data[HDD_INFO_MIRROR:HDD_INFO_MIRROR + 0x40]
                actions.append(f'HDD Info: REPAIRED from donor')
                restored = True
        # Fallback scan donors_dir
        if not restored and donors_dir and os.path.isdir(donors_dir):
            for fname in sorted(os.listdir(donors_dir)):
                if not fname.upper().endswith('.BIN'):
                    continue
                try:
                    with open(os.path.join(donors_dir, fname), 'rb') as f:
                        d = f.read()
                    if len(d) >= HDD_INFO_MIRROR + 0x40:
                        di = _extract_hdd_info(d, HDD_INFO_OFF)
                        if di.get('clean') and di.get('has_data'):
                            nor_data[HDD_INFO_OFF:HDD_INFO_OFF + 0x40] = d[HDD_INFO_OFF:HDD_INFO_OFF + 0x40]
                            nor_data[HDD_INFO_MIRROR:HDD_INFO_MIRROR + 0x40] = d[HDD_INFO_MIRROR:HDD_INFO_MIRROR + 0x40]
                            actions.append(f'HDD Info: REPAIRED from {fname}')
                            restored = True
                            break
                except Exception:
                    continue
        if not restored:
            actions.append('HDD Info: FAILED (both copies corrupt, no clean donor)')

    # EAP HDD wrapped key: try backup, then donor
    if len(nor_data) >= HDD_KEY_BACKUP_BLOB + eap_key_size:
        primary_valid = _is_valid_eap(nor_data, HDD_KEY_MAGIC, eap_key_size)
        backup_valid = _is_valid_eap(nor_data, HDD_KEY_BACKUP_MAGIC, eap_key_size)

        if not primary_valid and backup_valid:
            nor_data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + eap_key_size] = (
                nor_data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + eap_key_size]
            )
            actions.append('EAP HDD Key: RESTORED from backup')
        elif primary_valid and not backup_valid:
            nor_data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + eap_key_size] = (
                nor_data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + eap_key_size]
            )
            actions.append('EAP HDD Key backup: RESTORED from primary')
        elif not primary_valid and not backup_valid:
            restored = False
            if donor_data and len(donor_data) >= HDD_KEY_BACKUP_BLOB + 0x60:
                donor_size = detect_eap_key_size(donor_data)
                if _is_valid_eap(donor_data, HDD_KEY_MAGIC, donor_size):
                    nor_data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + eap_key_size] = (
                        donor_data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + donor_size][:4 + eap_key_size]
                    )
                    nor_data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + eap_key_size] = (
                        donor_data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + donor_size][:4 + eap_key_size]
                    )
                    actions.append('EAP HDD Key: REPAIRED from donor')
                    restored = True
            if not restored and donors_dir and os.path.isdir(donors_dir):
                for fname in sorted(os.listdir(donors_dir)):
                    if not fname.upper().endswith('.BIN'):
                        continue
                    fpath = os.path.join(donors_dir, fname)
                    try:
                        with open(fpath, 'rb') as f:
                            d = f.read()
                        if len(d) >= HDD_KEY_BACKUP_BLOB + 0x60:
                            donor_size = detect_eap_key_size(d)
                            if _is_valid_eap(d, HDD_KEY_MAGIC, donor_size):
                                nor_data[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + eap_key_size] = (
                                    d[HDD_KEY_MAGIC:HDD_KEY_MAGIC + 4 + donor_size][:4 + eap_key_size]
                                )
                                nor_data[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + eap_key_size] = (
                                    d[HDD_KEY_BACKUP_MAGIC:HDD_KEY_BACKUP_MAGIC + 4 + donor_size][:4 + eap_key_size]
                                )
                                actions.append(f'EAP HDD Key: REPAIRED from {fname}')
                                restored = True
                                break
                    except Exception:
                        continue
            if not restored:
                actions.append('EAP HDD Key: FAILED (no valid donor found)')

    if not actions:
        actions.append('HDD Metadata: OK (no repair needed)')

    return actions


def format_hdd_report(analysis: Dict) -> str:
    lines = []
    lines.append(f'{C.CYN}{"=" * 60}{C.RST}')
    lines.append(title('  NVS / HDD METADATA ANALYSIS'))
    lines.append(f'{C.CYN}{"=" * 60}{C.RST}')

    ser = analysis.get("console_serial") or "Not detected"
    hdd_m = analysis.get("hdd_model") or "Not detected"
    hdd_s = analysis.get("hdd_serial") or "Not detected"
    lines.append(f'\n  Console Serial:  {value(ser)}')
    lines.append(f'  HDD Model:       {value(hdd_m)}')
    lines.append(f'  HDD Serial:      {value(hdd_s)}')
    lines.append(f'  HDD Info Clean:  {status_bool(analysis["hdd_info_clean"])}')
    lines.append(f'  HDD Keys Valid:  {status_bool(analysis["keys_valid"])}')
    lines.append(f'  HDD Meta Synced: {status_bool(analysis["mirror_synced"])}')
    lines.append(f'  Overall NVS:     {status_bool(analysis["healthy"])}')

    lines.append(f'\n  {info("--- NVS Sub-Regions ---")}')
    for off in sorted(analysis['nvs_subregions']):
        r = analysis['nvs_subregions'][off]
        status_label = ok('OK') if r['healthy'] else fail('CORRUPT')
        lines.append(f'  0x{NVS_START + off:05X} ({r["name"]:20s}): {status_label}  ({r["non_zero"]:4d} bytes, entropy {r["entropy"]:.2f})')

    if analysis.get('notes'):
        lines.append(f'\n  {dim("Notes:")}')
        for n in analysis['notes']:
            lines.append(f'    {dim("-")} {n}')

    if analysis['warnings']:
        lines.append(f'\n  {warn("Warnings:")}')
        for w in analysis['warnings']:
            lines.append(f'    {warn("-")} {w}')

    if analysis['recommendations']:
        lines.append(f'\n  {info("Recommendations:")}')
        for r in analysis['recommendations']:
            lines.append(f'    {info("-")} {r}')

    lines.append(f'\n{C.CYN}{"=" * 60}{C.RST}')
    return '\n'.join(lines)

