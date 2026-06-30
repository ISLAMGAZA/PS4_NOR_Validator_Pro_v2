"""
Syscon Regeneration — Rebuild Syscon from donor when original is lost or corrupted.
Uses Chip-matched donor firmware area (0x000-0x60000) + adjusted SNVS (0x60000+).
"""

import os
import hashlib


FW_AREA_SIZE = 0x60000
SNVS_OFF = 0x60000
VALID_SIZES = (0x40000, 0x80000)
AREA0_FLAT = 0x60800
AREA0_ENTRIES = 0x60C00
AREA_SIZE = 0x1800
FLAT_SIZE = 0x400
ENTRY_SIZE = 16


class SysconDonorInfo:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.size = 0
        self.chip_hash = None
        self.fw_count = 0
        self.last_fw_data = None
        self.last_fw_ctr = 0
        self.match_score = -1
        self.match_reason = ''

    def __repr__(self):
        return (f'SysconDonorInfo({self.filename}, {self.size}B, '
                f'{self.fw_count} FW recs, score={self.match_score})')


def _chip_fingerprint(data, size=0x100):
    return hashlib.md5(data[:size]).hexdigest()


def _count_snvs(size, data):
    """Count FW records in SNVS. Falls back if SysconSNVSPatcher unavailable."""
    try:
        from ..patchers.syscon_patcher import SysconSNVSPatcher
        sp = SysconSNVSPatcher(data)
        snvs = sp.analyze_snvs()
        records = sp.find_fw_records()
        last_data = records[-1]['fw_a'][3] if records else None
        last_ctr = records[-1]['fw_a'][2] if records else 0
        return snvs['fw_record_count'], snvs['total_entries'], last_data, last_ctr
    except Exception:
        return 0, 0, None, 0


class SysconDonorDB:
    def __init__(self, directory):
        self.directory = directory
        self.donors = []
        self._by_chip = {}

    def scan(self):
        if not os.path.isdir(self.directory):
            return []
        self.donors = []
        self._by_chip = {}
        for fname in sorted(os.listdir(self.directory)):
            if not fname.upper().endswith('.BIN'):
                continue
            fpath = os.path.join(self.directory, fname)
            sz = os.path.getsize(fpath)
            if sz not in VALID_SIZES:
                continue
            info = SysconDonorInfo(fpath)
            info.size = sz
            try:
                with open(fpath, 'rb') as f:
                    data = f.read()
            except Exception:
                continue
            info.chip_hash = _chip_fingerprint(data)
            info.fw_count, entries, ld, lc = _count_snvs(sz, data)
            info.last_fw_data = ld
            info.last_fw_ctr = lc
            self.donors.append(info)
            self._by_chip.setdefault(info.chip_hash, []).append(info)
        return self.donors

    @property
    def count(self):
        return len(self.donors)

    def _detect_nor_info(self, nor_data):
        from ..utils.helpers import detect_sku, detect_fw_version
        sku = detect_sku(nor_data)
        fw = detect_fw_version(nor_data)
        return sku, fw

    def _nor_sku_to_chip(self, sku):
        """Map NOR SKU prefix to expected syscon chip type.
        Prefers exact model prefix match, falls back to range."""
        if not sku or sku == 'Unknown':
            return None
        from ..v2_features.syscon_fw_db import SYSCON_CHIPS
        import re
        m = re.match(r'CUH-(\d{2})', sku)
        if not m:
            return None
        mn = int(m.group(1))

        # First pass: exact model number match
        for chip_name, info in SYSCON_CHIPS.items():
            for m_str in info['models']:
                m_match = re.match(r'CUH-(\d{2})', m_str)
                if m_match and int(m_match.group(1)) == mn:
                    return chip_name

        # Second pass: range-based match
        for chip_name, info in SYSCON_CHIPS.items():
            for m_str in info['models']:
                m_match = re.match(r'CUH-(\d{2})', m_str)
                if not m_match:
                    continue
                m_base = int(m_match.group(1))
                if m_base <= mn <= m_base + 9:
                    return chip_name
        return None

    def match(self, nor_data):
        """Rank donors by chip match and FW compatibility.
        Groups by chip fingerprint first, then ranks within group."""
        sku, fw = self._detect_nor_info(nor_data)
        target_chip = self._nor_sku_to_chip(sku)

        if not self.donors:
            return []

        # Build chip_hash groups from all donors
        chip_groups = {}
        for d in self.donors:
            chip_groups.setdefault(d.chip_hash, []).append(d)

        # Determine which chip group best matches the target
        best_chip_hash = None
        best_chip_score = -1

        # Try to detect chip types from donor data
        donor_chip_types = {}
        for ch, group in chip_groups.items():
            sample = group[0]
            try:
                with open(sample.filepath, 'rb') as f:
                    raw = f.read()[:FW_AREA_SIZE]
                from ..v2_features.syscon_fw_db import detect_syscon_fw
                sc_info = detect_syscon_fw(raw)
                donor_chip_types[ch] = sc_info.get('chip', 'Unknown')
            except Exception:
                donor_chip_types[ch] = 'Unknown'

        for ch, chip_name in donor_chip_types.items():
            if chip_name != 'Unknown' and target_chip:
                if chip_name == target_chip:
                    best_chip_hash = ch
                    best_chip_score = 100
                    break
                else:
                    score = 30
                    if best_chip_score < score:
                        best_chip_hash = ch
                        best_chip_score = score
            else:
                score = 50
                if best_chip_score < score:
                    best_chip_hash = ch
                    best_chip_score = score

        # If no best found, use the most common chip group
        if best_chip_hash is None and chip_groups:
            best_chip_hash = max(chip_groups.keys(),
                                 key=lambda ch: len(chip_groups[ch]))

        # Score each donor within the matched chip group
        for d in self.donors:
            try:
                with open(d.filepath, 'rb') as f:
                    data = f.read()[:FW_AREA_SIZE]
            except Exception:
                d.match_score = -1
                continue

            score = 0
            reasons = []

            # Chip group match (highest weight)
            chip_name = donor_chip_types.get(d.chip_hash, 'Unknown')
            if d.chip_hash == best_chip_hash:
                if chip_name != 'Unknown':
                    score += 100
                    reasons.append(f'chip={chip_name}')
                else:
                    score += 80
                    reasons.append('chip_group_match')
            else:
                score += 5
                reasons.append('chip_diff')

            # FW record count - more records usually means more complete
            if d.fw_count > 50:
                score += 10
                reasons.append(f'{d.fw_count}recs')
            elif d.fw_count > 20:
                score += 5
                reasons.append(f'{d.fw_count}recs')
            else:
                score += 1
                reasons.append(f'{d.fw_count}recs')

            # Prefer same-size
            if d.size == 0x80000:
                score += 2
                reasons.append('512KB')

            d.match_score = score
            d.match_reason = ', '.join(reasons)

        scored = [d for d in self.donors if d.match_score >= 0]
        scored.sort(key=lambda x: x.match_score, reverse=True)
        self._last_ranked = scored
        return scored

    def _fw_to_int(self, v):
        try:
            parts = v.split('.')
            return int(parts[0]) * 100 + int(parts[1])
        except (ValueError, IndexError):
            return 0


def syscon_regenerate(nor_data, donor_data, method='auto'):
    """
    Regenerate Syscon from donor.
    Keeps donor firmware area (0x000-0x60000).
    Adjusts SNVS (0x60000+) to match target NOR.
    """
    size = len(donor_data)
    if size not in VALID_SIZES:
        return None, 'invalid donor size'

    result = bytearray(donor_data)
    report = []

    # Step 1: Apply SNVS adjustment via Method A/B
    from ..patchers.syscon_patcher import SysconSNVSPatcher
    from ..utils.helpers import detect_fw_version

    sp = SysconSNVSPatcher(bytes(result))
    records = sp.find_fw_records()

    nor_fw = detect_fw_version(nor_data)
    report.append(f'Target NOR FW: {nor_fw}')

    if len(records) < 2:
        return bytes(result), 'donor has < 2 FW records — returned as-is'

    report.append(f'Donor FW records: {len(records)}')

    # Auto-detect: compare NOR FW with donor's last record
    # We can't decode the record data, so we try Method A (remove last record)
    # This is the cleanest approach for most cases
    if method == 'auto':
        last_fw_data = records[-1]['fw_a'][3]
        new_last_fw_data = records[-2]['fw_a'][3]

        # Check NOR identity data in syscon area
        bid = nor_data[0x1C4000:0x1C4008] if len(nor_data) > 0x1C4008 else None
        if bid and len(bid) == 8 and not all(b in (0x00, 0xFF) for b in bid):
            # Board ID presence suggests the syscon donor might not match
            pass

        result_data = sp.remove_last_fw_record()
        report.append(f'Applied Method A: removed last FW record (ctr={records[-1]["fw_a"][2]})')
        report.append(f'New last record FW_A data: {new_last_fw_data.hex()}')
        return bytes(result_data), '\n'.join(report)

    elif method == 'B':
        # Method B: remove entries only, keep flatdata
        if len(records) < 2:
            return bytes(result), 'A (fallback from B)'
        last = records[-1]
        for entry in [last['fw_a'], last['fw_b'], last['lic1'], last['lic2']]:
            pos = entry[0]
            if pos + 16 <= len(result):
                result[pos:pos + 16] = b'\xFF' * 16
        report.append(f'Applied Method B: removed last FW record entries')
        return bytes(result), '\n'.join(report)

    return bytes(result), 'no method applied'


def wee_rebuild(syscon_data, keep_types=None):
    """
    Rebuild Syscon SNVS using WeeTools PRO algorithm (6->4->3 "keep same FW").
    
    1. Parses all 16-byte entries from SNVS (0x60000-0x7FFFF)
    2. For each type, keeps the entry with the highest counter
    3. Selects types to keep: 0x00-0x0B (12 base entries) + 0x28-0x2B (4 FW entries)
    4. Builds clean Area 0 flatdata + entries, fills rest with 0xFF
    5. Returns the rebuilt syscon as bytes
    
    Args:
        syscon_data: Full syscon dump (256KB or 512KB)
        keep_types: Optional list of type values to keep.
                    Default: [0x00..0x0B] + [0x28..0x2B]
    Returns:
        (rebuilt_bytes, report_string)
    """
    size = len(syscon_data)
    if size not in VALID_SIZES:
        return None, 'invalid syscon size'

    # Default: keep types 0x00-0x0B + 0x28-0x2B
    if keep_types is None:
        keep_types = list(range(0x00, 0x0C)) + list(range(0x28, 0x2C))

    # Step 1: Parse all 16-byte entries from valid area entry ranges
    # 9 areas, each: flatdata (0x400 bytes) + entries (0x1400 bytes)
    AREA_COUNT = 9
    entries_by_type = {}
    for area_n in range(AREA_COUNT):
        astart = SNVS_OFF + 0x800 + area_n * AREA_SIZE
        for i in range(FLAT_SIZE, AREA_SIZE, ENTRY_SIZE):
            off = astart + i
            if off + ENTRY_SIZE > size:
                break
            raw = syscon_data[off:off + ENTRY_SIZE]
            if raw[0] == 0xA5 and raw[7] == 0xC3:
                typ = raw[1] | (raw[2] << 8)
                ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                data = raw[8:16]
                if typ not in entries_by_type or ctr > entries_by_type[typ][0]:
                    entries_by_type[typ] = (ctr, data)

    report_parts = [f'Parsed {len(entries_by_type)} unique entry types from SNVS']

    # Step 2: Select entries for keep_types
    # Only keep types that actually exist in the original data.
    # If a keep_type doesn't exist, simply skip it — creating empty
    # entries (all zeros) is worse than omitting them.
    selected = {}
    for typ in keep_types:
        if typ in entries_by_type:
            selected[typ] = entries_by_type[typ]

    # If no keep_type matched, fall back to keeping all available types
    if not selected and entries_by_type:
        for typ in sorted(entries_by_type.keys())[:16]:
            selected[typ] = entries_by_type[typ]
        report_parts.append(f'No standard types found; kept {len(selected)} best-match types as fallback')
    else:
        kept = len(selected)
        skipped = len(entries_by_type) - kept
        report_parts.append(f'Kept {kept} types, skipped {max(0, skipped)} types')

    # Step 3: Build new SNVS
    # WeeTools pattern:
    #   - Keep header 0x60000-0x6000F (first 16 bytes)
    #   - Clear header 0x60010-0x6007F
    #   - Clear Areas 0-7 (0x60800-0x6DFFF) then rebuild Area 0
    #   - Keep Areas 8+ (0x6E000+) from original
    result = bytearray(size)
    result[:] = syscon_data

    # Clear header: keep first 0x10 bytes, clear 0x60010-0x6007F
    header_clear_end = min(0x60080, size)
    if header_clear_end > SNVS_OFF + 0x10:
        result[SNVS_OFF + 0x10:header_clear_end] = b'\xFF' * (header_clear_end - SNVS_OFF - 0x10)

    # Clear Areas 0-7 (flatdata + entries)
    for area_n in range(8):
        astart = SNVS_OFF + 0x800 + area_n * AREA_SIZE
        aend = astart + AREA_SIZE
        if aend <= size:
            result[astart:aend] = b'\xFF' * AREA_SIZE
        elif astart < size:
            result[astart:size] = b'\xFF' * (size - astart)

    # Step 4: Write flatdata indexed by type*8
    sorted_types = sorted(selected.keys())
    for typ in sorted_types:
        ctr, data = selected[typ]
        fd_offset = AREA0_FLAT + typ * 8
        if fd_offset + 8 <= size:
            result[fd_offset:fd_offset + 8] = data

    # Step 5: Write entries at 0x60C00+ with sequential counters
    for i, typ in enumerate(sorted_types, 1):
        ctr, data = selected[typ]
        entry_off = AREA0_ENTRIES + (i - 1) * ENTRY_SIZE
        if entry_off + ENTRY_SIZE > size:
            break
        result[entry_off] = 0xA5
        result[entry_off + 1] = typ & 0xFF
        result[entry_off + 2] = (typ >> 8) & 0xFF
        result[entry_off + 3] = 0xFF
        result[entry_off + 4] = i & 0xFF
        result[entry_off + 5] = (i >> 8) & 0xFF
        result[entry_off + 6] = (i >> 16) & 0xFF
        result[entry_off + 7] = 0xC3
        result[entry_off + 8:entry_off + 16] = data

    report_parts.append(f'Wrote {len(sorted_types)} entries with counters 1-{len(sorted_types)}')
    report_parts.append(f'Flatdata at 0x{AREA0_FLAT:05x}, types: {", ".join(f"0x{t:02x}" for t in sorted_types)}')

    return bytes(result), '\n'.join(report_parts)


def detect_target_nor(nor_data):
    """Extract NOR identity for matching."""
    from ..utils.helpers import detect_sku, detect_fw_version
    info = {
        'sku': detect_sku(nor_data),
        'fw': detect_fw_version(nor_data),
        'board_id': None,
        'mac': None,
    }
    if len(nor_data) > 0x1C4027:
        info['board_id'] = nor_data[0x1C4000:0x1C4008].hex()
        info['mac'] = nor_data[0x1C4021:0x1C4027].hex()
    return info


def syscon_generate_snvs(syscon_data, chip_type, target_arv):
    """
    Generate clean SNVS from scratch with a specific anti-rollback value.
    Used when the original SNVS is completely damaged/unreadable.

    Creates 17 entries: types 0x00-0x0B (12 base) + 0x0C (PRE0 with target_arv)
    + 0x28-0x2B (4 FW records), similar to WeeTools Rebuild but with
    explicit PRE0 entry for correct ARV.

    Args:
        syscon_data: Original syscon (firmware area preserved, SNVS rebuilt)
        chip_type: Chip name string (CXD90025G/CXD90044G/CXD90068G)
        target_arv: Anti-rollback version byte (0-255) for PRE0 entry

    Returns:
        (rebuilt_bytes, report_string)
    """
    size = len(syscon_data)
    if size not in VALID_SIZES:
        return None, f'invalid syscon size {size}'

    # Types: 0x00-0x0B (12 base) + 0x0C (PRE0/eFuse with ARV) + 0x28-0x2B (4 FW)
    keep_types = list(range(0x00, 0x0C)) + [0x0C] + list(range(0x28, 0x2C))

    # Build data for each type
    typed_data = {}
    for typ in keep_types:
        if typ == 0x0C:
            # PRE0: first byte = ARV, rest = 0x00
            typed_data[typ] = bytes([target_arv & 0xFF]) + b'\x00' * 7
        else:
            typed_data[typ] = b'\x00' * 8

    result = bytearray(size)
    result[:] = syscon_data

    # Preserve header first 0x10 bytes, clear 0x60010-0x6007F
    header_clear_end = min(0x60080, size)
    if header_clear_end > SNVS_OFF + 0x10:
        result[SNVS_OFF + 0x10:header_clear_end] = b'\xFF' * (header_clear_end - SNVS_OFF - 0x10)

    # Clear Areas 0-7 (flatdata + entries)
    for area_n in range(8):
        astart = SNVS_OFF + 0x800 + area_n * AREA_SIZE
        aend = astart + AREA_SIZE
        if aend <= size:
            result[astart:aend] = b'\xFF' * AREA_SIZE
        elif astart < size:
            result[astart:size] = b'\xFF' * (size - astart)

    # Write flatdata indexed by type*8
    sorted_types = sorted(typed_data.keys())
    for typ in sorted_types:
        data = typed_data[typ]
        fd_offset = AREA0_FLAT + typ * 8
        if fd_offset + 8 <= size:
            result[fd_offset:fd_offset + 8] = data

    # Write entries with sequential counters 1-17
    for i, typ in enumerate(sorted_types, 1):
        data = typed_data[typ]
        entry_off = AREA0_ENTRIES + (i - 1) * 16
        if entry_off + 16 > size:
            break
        result[entry_off] = 0xA5
        result[entry_off + 1] = typ & 0xFF
        result[entry_off + 2] = (typ >> 8) & 0xFF
        result[entry_off + 3] = 0xFF
        result[entry_off + 4] = i & 0xFF
        result[entry_off + 5] = (i >> 8) & 0xFF
        result[entry_off + 6] = (i >> 16) & 0xFF
        result[entry_off + 7] = 0xC3
        result[entry_off + 8:entry_off + 16] = data

    report_parts = [
        f'Generated clean SNVS with {len(sorted_types)} entries',
        f'Target ARV (PRE0): {target_arv}',
        f'Types: {", ".join(f"0x{t:02x}" for t in sorted_types)}',
        f'Chip: {chip_type or "Unknown"}',
    ]
    return bytes(result), '\n'.join(report_parts)


def _check_firmware_area_health(data):
    """Check if syscon firmware area (0x000-0x60000) is intact."""
    if len(data) < 0x60000:
        return False, 'data too small'
    fw = data[:0x60000]
    # Check not all 0xFF or all 0x00
    if all(b == 0xFF for b in fw):
        return False, 'firmware area all 0xFF (erased)'
    if all(b == 0x00 for b in fw):
        return False, 'firmware area all 0x00 (blank)'
    # RL78 firmware starts with interrupt vector table (reset vector at 0x0000)
    # Typical first 4 bytes: 80 01 FF FF (vector table entries)
    if fw[0] not in (0x80, 0x00, 0xFF):
        return False, f'firmware area invalid first byte 0x{fw[0]:02X}'
    # Count non-0xFF bytes as rough health indicator
    non_ff = sum(1 for b in fw if b != 0xFF)
    if non_ff < 0x100:
        return False, f'firmware area too sparse ({non_ff} non-0xFF bytes)'
    return True, f'firmware area intact ({non_ff} non-0xFF bytes)'


def _count_snvs_entries(data, max_area=7):
    """Count valid SNVS entries in Areas 0-max_area as health indicator.
    Areas 0-7 are the main SNVS region; Areas 8+ are preserved but may be stale."""
    if len(data) < 0x60800:
        return 0, 0, 0
    count = 0
    seen_types = set()
    max_ctr = 0
    for area_n in range(max_area + 1):
        astart = SNVS_OFF + 0x800 + area_n * AREA_SIZE
        for i in range(0x400, AREA_SIZE, 16):
            off = astart + i
            if off + 16 > len(data):
                break
            raw = data[off:off + 16]
            if raw[0] == 0xA5 and raw[7] == 0xC3:
                typ = raw[1] | (raw[2] << 8)
                ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                count += 1
                seen_types.add(typ)
                if ctr > max_ctr:
                    max_ctr = ctr
    return count, len(seen_types), max_ctr


def _find_target_arv(nor_data, syscon_data, chip_type):
    """
    Determine target ARV for rebuild.
    Priority:
    1. Extract from existing PRE0 entries in Areas 0-7 (current SNVS)
    2. Extract from preserved PRE0 entries in Areas 8+ (original data)
    3. Look up from ARV_FW_MAP using chip + NOR FW
    4. Fallback to ARV=0
    """
    def _scan_arv(start_area, end_area):
        """Scan PRE0 entries in given area range, return (arv, ctr) or (-1, -1).
        Checks multiple possible PRE0 type values (standard 0x0C and common
        non-standard variants like 0x1B observed in some syscon formats).
        Prefers type 0x0C (standard) over non-standard types."""
        best_arv = -1
        best_ctr = -1
        best_typ = -1
        # PRE0 can appear at different byte1 values depending on syscon format.
        # Standard WeeTools: type 0x0C. Some OEM formats: type 0x1B.
        pre0_types = {0x0C, 0x1B, 0x14, 0x18}
        for area_n in range(start_area, end_area):
            astart = SNVS_OFF + 0x800 + area_n * AREA_SIZE
            for i in range(0x400, AREA_SIZE, 16):
                off = astart + i
                if off + 16 > len(syscon_data):
                    break
                raw = syscon_data[off:off + 16]
                if raw[0] == 0xA5 and raw[7] == 0xC3:
                    typ = raw[1] | (raw[2] << 8)
                    ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                    if typ in pre0_types:
                        # Prioritize standard type 0x0C over non-standard variants
                        if best_arv < 0 or ctr > best_ctr:
                            if best_arv < 0 or best_typ != 0x0C or typ == 0x0C:
                                best_ctr = ctr
                                best_arv = raw[8]
                                best_typ = typ
        return best_arv, best_ctr

    # Method 1: Extract ARV from PRE0 entries in Areas 0-7 (current SNVS)
    try:
        arv, ctr = _scan_arv(0, 8)
        if arv >= 0:
            return arv, f'extracted from Areas 0-7 PRE0 (ctr={ctr}, ARV={arv})'
    except Exception:
        pass

    # Method 2: Extract from preserved Areas 8+ (original SNVS remnants)
    try:
        arv, ctr = _scan_arv(8, 16)
        if arv >= 0:
            return arv, f'extracted from preserved Areas 8+ PRE0 (ctr={ctr}, ARV={arv})'
    except Exception:
        pass

    # Method 3: Look up from ARV_FW_MAP
    try:
        from arv_fw_map import ARV_FW_MAP
        from ..utils.helpers import detect_fw_version
        nor_fw = detect_fw_version(nor_data)
        if chip_type and nor_fw and nor_fw != '0.00':
            for (chip, arv), expected_fws in ARV_FW_MAP.items():
                if chip == chip_type and nor_fw in expected_fws:
                    return arv, f'looked up from ARV_FW_MAP: {chip_type} FW={nor_fw} -> ARV={arv}'
    except ImportError:
        pass
    except Exception:
        pass

    return 0, 'fallback: ARV=0 (no mapping available)'


def syscon_rebuild_from_nor(nor_data, syscon_data, fws_dir=None, donors_dir=None, syscon_donors_dir=None):
    """
    Full syscon rebuild from NOR — handles all damage scenarios.

    Scenarios:
    A: Firmware damaged + SNVS damaged → find best donor, generate SNVS with ARV from NOR
    B: Firmware OK + SNVS damaged → keep firmware, WeeTools rebuild or generate SNVS
    C: Firmware OK + SNVS OK → already healthy, return as-is

    Args:
        nor_data: 32MB NOR dump
        syscon_data: Syscon dump (256KB or 512KB)
        fws_dir: Optional firmware blobs directory (unused currently)
        donors_dir: Optional NOR donors directory (unused currently)
        syscon_donors_dir: Optional syscon donors directory for Scenario A

    Returns:
        (rebuilt_bytes, report_string)
    """
    from ..utils.helpers import detect_sku, detect_fw_version
    report = []
    result = bytearray(syscon_data)
    size = len(syscon_data)

    # Step 1: Detect NOR identity
    sku = detect_sku(nor_data)
    nor_fw = detect_fw_version(nor_data)
    report.append(f'NOR: SKU={sku}, FW={nor_fw}')

    # Step 2: Map SKU to chip type
    chip_type = None
    if sku and sku != 'Unknown':
        db = SysconDonorDB('')
        chip_type = db._nor_sku_to_chip(sku)
    report.append(f'Target chip: {chip_type or "Unknown"}')

    # Step 3: Check syscon health
    fw_ok, fw_detail = _check_firmware_area_health(syscon_data)
    snvs_count_a0, snvs_types_a0, snvs_max_ctr_a0 = _count_snvs_entries(syscon_data, max_area=0)
    snvs_count_all, snvs_types_all, snvs_max_ctr_all = _count_snvs_entries(syscon_data, max_area=7)
    
    # Area 0 needs at least 12 entries (core types 0x00-0x0B) to be healthy
    area0_healthy = snvs_count_a0 >= 12

    report.append(f'Firmware area: {fw_detail}')
    report.append(f'SNVS Area 0: {snvs_count_a0} entries, {snvs_types_a0} unique types, max_ctr={snvs_max_ctr_a0}')
    report.append(f'SNVS Areas 0-7: {snvs_count_all} entries, {snvs_types_all} unique types')

    # Step 4: Determine target ARV
    target_arv, arv_detail = _find_target_arv(nor_data, syscon_data, chip_type)
    report.append(f'Target ARV: {target_arv} ({arv_detail})')

    # Step 5: Choose rebuild strategy
    if fw_ok and area0_healthy:
        report.append('Syscon already healthy (Area 0 intact) — no rebuild needed')
        return bytes(result), '\n'.join(report)

    if fw_ok and not area0_healthy:
        # Scenario B: SNVS damaged, firmware OK
        report.append('Scenario B: SNVS damaged, firmware intact')
        rebuilt, sub_report = syscon_generate_snvs(syscon_data, chip_type, target_arv)
        if rebuilt is None:
            # Fallback to wee_rebuild
            rebuilt, sub_report = wee_rebuild(syscon_data)
        if rebuilt is not None:
            report.append(sub_report)
            return rebuilt, '\n'.join(report)
        report.append('WARNING: all SNVS regeneration methods failed')

    # Scenario A: firmware damaged (or both)
    if not fw_ok:
        report.append(f'Scenario A: firmware area damaged — {fw_detail}')

    if syscon_donors_dir:
        report.append('Searching for best donor match...')
        db = SysconDonorDB(syscon_donors_dir)
        donors = db.scan()
        ranked = db.match(nor_data)

        if ranked:
            best = ranked[0]
            report.append(f'Top donor: {best.filename} (score={best.match_score}, {best.match_reason})')
            try:
                with open(best.filepath, 'rb') as f:
                    donor_data = f.read()
                # Use donor firmware area
                result[:0x60000] = donor_data[:0x60000]
                report.append(f'Copied firmware area from donor: {best.filename}')
            except Exception as e:
                report.append(f'Failed to read donor: {e}')
        else:
            report.append('No suitable donor found')

    # Regenerate SNVS on the (possibly donor-based) result
    rebuilt, sub_report = syscon_generate_snvs(bytes(result), chip_type, target_arv)
    if rebuilt is not None:
        report.append(sub_report)
        return rebuilt, '\n'.join(report)

    # Last resort: WeeTools rebuild
    rebuilt, sub_report = wee_rebuild(bytes(result))
    if rebuilt is not None:
        report.append(sub_report)
        return rebuilt, '\n'.join(report)

    return bytes(result), '\n'.join(report)


def syscon_light_repair(syscon_data):
    """
    Light repair — fix SNVS header and flatdata/entry consistency.
    Used when damage is minor (corrupted header, mismatched flatdata).
    Preserves all original entries and data.
    """
    size = len(syscon_data)
    if size not in VALID_SIZES:
        return None, 'invalid syscon size'

    result = bytearray(syscon_data)
    report = []
    repairs = 0

    # 1. Fix header at 0x60000: first 2 entries should have A5/C3 markers
    hdr = result[SNVS_OFF:SNVS_OFF + 16]
    fixed = False

    if hdr[0] != 0xA5:
        result[SNVS_OFF] = 0xA5
        fixed = True
    if hdr[7] != 0xC3:
        result[SNVS_OFF + 7] = 0xC3
        fixed = True
    if hdr[8] != 0xA5:
        result[SNVS_OFF + 8] = 0xA5
        fixed = True
    if hdr[15] != 0xC3:
        result[SNVS_OFF + 15] = 0xC3
        fixed = True

    if fixed:
        repairs += 1
        report.append('Fixed SNVS header markers')

    # 2. Check first entry type (should be 0x00)
    entry0_type = result[SNVS_OFF + 1] | (result[SNVS_OFF + 2] << 8)
    if entry0_type != 0x00:
        result[SNVS_OFF + 1] = 0x00
        result[SNVS_OFF + 2] = 0x00
        repairs += 1

    # 3. Fix flatdata for known types if entries exist but flatdata is missing
    entries = _scan_entries_all(result)
    if entries:
        fixed_fd = 0
        for typ, data, _ in entries:
            fd_off = AREA0_FLAT + typ * 8
            if fd_off + 8 <= size:
                fd_slot = result[fd_off:fd_off + 8]
                if all(b in (0x00, 0xFF) for b in fd_slot):
                    result[fd_off:fd_off + 8] = data
                    fixed_fd += 1
        if fixed_fd:
            repairs += 1
            report.append(f'Fixed {fixed_fd} flatdata slots from entry data')

    if repairs == 0:
        report.append('No light repairs needed')

    report.append(f'Total repairs: {repairs}')
    return bytes(result), '\n'.join(report)


def _scan_entries_all(data):
    """Scan entries returning (type, data, counter) for unique highest-counter entries."""
    entries = {}
    for area_n in range(16):
        astart = SNVS_OFF + 0x800 + area_n * AREA_SIZE
        for i in range(FLAT_SIZE, AREA_SIZE, ENTRY_SIZE):
            off = astart + i
            if off + ENTRY_SIZE > len(data):
                break
            raw = data[off:off + ENTRY_SIZE]
            if raw[0] == 0xA5 and raw[7] == 0xC3:
                typ = raw[1] | (raw[2] << 8)
                ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                if typ not in entries or ctr > entries[typ][1]:
                    entries[typ] = (raw[8:16], ctr)
    return [(typ, data, ctr) for typ, (data, ctr) in entries.items()]


def syscon_auto_repair(syscon_data, nor_data=None, syscon_donors_dir=None):
    """
    Auto-detect damage and apply appropriate repair.
    Full automatic flow with detailed report.

    Args:
        syscon_data: Raw syscon dump
        nor_data: Optional NOR dump for ARV lookup + donor matching
        syscon_donors_dir: Optional syscon donors directory

    Returns:
        (repaired_bytes, report_string, recommendation_int)
    """
    from ..v2_features.syscon_analyzer import analyze_syscon, REPAIR_LEVELS

    report = ['=== SYSCON AUTO REPAIR ===']
    report.append('')

    # Step 1: Analyze
    analysis = analyze_syscon(syscon_data, nor_data)
    report.append(analysis.summary)
    report.append(f'Severity: {analysis.severity}')
    report.append(f'Recommended level: {analysis.recommendation} ({REPAIR_LEVELS.get(analysis.recommendation, "None")})')
    report.append('')

    level = analysis.recommendation

    # Step 2: Execute repair at recommended level
    result = None
    sub_report = ''

    if level == 0:
        report.append('Syscon appears healthy — no repair needed')
        return syscon_data, '\n'.join(report), 0

    elif level == 1:
        report.append('Applying Light Repair...')
        result, sub_report = syscon_light_repair(syscon_data)

    elif level == 2:
        report.append('Applying Medium Repair (WeeTools Rebuild)...')
        result, sub_report = wee_rebuild(syscon_data)
        if result is not None:
            # After WeeTools, check how many entries we have
            entry_count = 0
            for i in range(320):
                off = 0x60C00 + i * 16
                if off + 16 > len(result): break
                if result[off] != 0xA5: break
                entry_count += 1
            report.append(f'WeeTools produced {entry_count} entries')

            # If we're missing core types (0x00-0x07), use generate_snvs but
            # preserve any existing data from WeeTools output
            if entry_count < 12:
                report.append('Missing core types detected — generating defaults...')
                import copy
                gen_bytes, sub_report2 = syscon_generate_snvs(bytes(result), None, 0)
                if gen_bytes:
                    gen = bytearray(gen_bytes)
                    # Merge: copy WeeTools-generated data into the full SNVS
                    for i in range(320):
                        off_wee = 0x60C00 + i * 16
                        if off_wee + 16 > len(result): break
                        wee_entry = bytes(result)[off_wee:off_wee+16]
                        if wee_entry[0] != 0xA5: break
                        wee_typ = wee_entry[1] | (wee_entry[2] << 8)

                        # Find same type in generate output and copy data
                        for j in range(320):
                            off_gen = 0x60C00 + j * 16
                            if off_gen + 16 > len(gen): break
                            gen_entry = gen[off_gen:off_gen+16]
                            if gen_entry[0] != 0xA5: break
                            gen_typ = gen_entry[1] | (gen_entry[2] << 8)
                            if gen_typ == wee_typ:
                                gen[off_gen + 8:off_gen + 16] = wee_entry[8:16]
                                break

                    result = bytes(gen)
                    sub_report += '\n' + sub_report2

    elif level == 3:
        # Heavy: SNVS regeneration with ARV
        report.append('Applying Heavy Repair (SNVS Regeneration)...')
        chip_type = None
        target_arv = 0

        if nor_data:
            from ..utils.helpers import detect_sku
            sku = detect_sku(nor_data)
            if sku and sku != 'Unknown':
                db = SysconDonorDB('')
                chip_type = db._nor_sku_to_chip(sku)
            target_arv, arv_detail = _find_target_arv(nor_data, syscon_data, chip_type)
            report.append(f'ARV: {target_arv} ({arv_detail})')
        else:
            # Try to get ARV from existing syscon
            target_arv, arv_detail = _find_target_arv(None, syscon_data, None)
            report.append(f'ARV: {target_arv} ({arv_detail})')

        result, sub_report = syscon_generate_snvs(syscon_data, chip_type, target_arv)

        if result is None:
            report.append('Heavy repair failed, falling back to WeeTools...')
            result, sub_report = wee_rebuild(syscon_data)

    elif level == 4:
        # Full: donor + SNVS regeneration
        report.append('Applying Full Repair (Donor + SNVS Regeneration)...')

        if not syscon_donors_dir:
            report.append('ERROR: syscon_donors_dir required for full repair')
            return syscon_data, '\n'.join(report), level

        chip_type = None
        target_arv = 0

        if nor_data:
            from ..utils.helpers import detect_sku
            sku = detect_sku(nor_data)
            if sku and sku != 'Unknown':
                db = SysconDonorDB('')
                chip_type = db._nor_sku_to_chip(sku)
            target_arv, arv_detail = _find_target_arv(nor_data, syscon_data, chip_type)
            report.append(f'ARV: {target_arv} ({arv_detail})')

        # Search donors
        db = SysconDonorDB(syscon_donors_dir)
        donors = db.scan()
        ranked = db.match(nor_data or syscon_data)

        if not ranked:
            report.append('No donors found')
            report.append('Falling back to Heavy Repair (SNVS only)...')
            result, sub_report = syscon_generate_snvs(syscon_data, chip_type, target_arv)
            if result is None:
                result, sub_report = wee_rebuild(syscon_data)
        else:
            best = ranked[0]
            report.append(f'Best donor: {best.filename} (score={best.match_score})')
            try:
                with open(best.filepath, 'rb') as f:
                    donor_data = f.read()
                result = bytearray(donor_data)
                result[0x60000:] = syscon_data[0x60000:]
                report.append(f'Copied firmware area from donor: {best.filename}')
            except Exception as e:
                report.append(f'Failed to read donor: {e}')
                result = bytearray(syscon_data)

            # Regenerate SNVS on donor-based result
            rebuilt, sub_report2 = syscon_generate_snvs(bytes(result), chip_type, target_arv)
            if rebuilt is not None:
                result = rebuilt
                sub_report = sub_report2
            else:
                rebuilt, sub_report2 = wee_rebuild(bytes(result))
                if rebuilt is not None:
                    result = rebuilt
                    sub_report = sub_report2

    if result is not None:
        if sub_report:
            report.append(sub_report)
        report.append(f'Repair completed at level {level}')

        # Final analysis
        final = analyze_syscon(result, nor_data)
        report.append(f'Final severity: {final.severity}')
        return result, '\n'.join(report), level

    report.append('ERROR: All repair methods failed')
    return syscon_data, '\n'.join(report), level
