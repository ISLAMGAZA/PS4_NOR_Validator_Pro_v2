"""
Syscon Damage Analyzer — deep scan of syscon dumps for corruption detection.
Classifies damage severity and recommends appropriate repair strategy.
"""

import struct

FW_SIZE = 0x60000
SNVS_OFF = 0x60000
AREA0_FLAT = 0x60800
AREA0_ENTRIES = 0x60C00
AREA_SIZE = 0x1800
FLAT_SIZE = 0x400
ENTRY_SIZE = 16
VALID_SIZES = (0x40000, 0x80000)


class DamageReport:
    def __init__(self):
        self.severity = 'none'
        self.summary = ''
        self.recommendation = 0

        self.firmware = {
            'healthy': False,
            'non_ff': 0,
            'size': 0,
            'first_byte': 0,
            'has_vectors': False,
            'detail': '',
        }

        self.snvs_header = {
            'healthy': False,
            'first_16': b'',
            'has_markers': False,
            'detail': '',
        }

        self.flatdata = {
            'healthy': False,
            'ff_percent': 0,
            'entries_match': False,
            'detail': '',
        }

        self.entries = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'unique_types': 0,
            'missing_types': [],
            'has_counter_anomalies': False,
            'has_preserved_areas': False,
            'detail': '',
        }

        self.preserved_areas = {
            'healthy': False,
            'valid_entries': 0,
            'has_preserved_fw_records': False,
            'detail': '',
        }

        self.damage_type = ''


def _parse_entry(raw):
    """Parse a single 16-byte SNVS entry. Returns dict or None."""
    if len(raw) < 16:
        return None
    if raw[0] != 0xA5 or raw[7] != 0xC3:
        return None
    typ = raw[1] | (raw[2] << 8)
    ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
    return {
        'type': typ,
        'counter': ctr,
        'data': raw[8:16],
        'offset': None,
    }


def _scan_entries(data, max_area=7):
    """Scan SNVS entries in given area range."""
    entries = []
    for area_n in range(max_area + 1):
        astart = SNVS_OFF + 0x800 + area_n * AREA_SIZE
        for i in range(FLAT_SIZE, AREA_SIZE, ENTRY_SIZE):
            off = astart + i
            if off + ENTRY_SIZE > len(data):
                break
            raw = data[off:off + ENTRY_SIZE]
            parsed = _parse_entry(raw)
            if parsed:
                parsed['offset'] = off
                entries.append(parsed)
    return entries


def _check_firmware(data):
    """Analyze firmware area (0x000-0x60000)."""
    result = {'healthy': False, 'non_ff': 0, 'first_byte': 0,
              'has_vectors': False, 'detail': ''}
    if len(data) < FW_SIZE:
        result['detail'] = 'data too small'
        return result

    fw = data[:FW_SIZE]
    result['size'] = FW_SIZE
    result['first_byte'] = fw[0]

    non_ff = sum(1 for b in fw if b != 0xFF)
    result['non_ff'] = non_ff

    if all(b == 0xFF for b in fw):
        result['detail'] = 'all 0xFF (erased)'
        return result
    if all(b == 0x00 for b in fw):
        result['detail'] = 'all 0x00 (blank)'
        return result
    if non_ff < 0x100:
        result['detail'] = f'too few non-FF bytes ({non_ff})'
        return result

    # Check RL78 interrupt vector table
    # Reset vector at 0x0000: 80 01 FF FF is typical
    if fw[0] == 0x80 and fw[1] == 0x01:
        result['has_vectors'] = True
    elif fw[0] == 0x80:
        result['has_vectors'] = True

    # Percentage of non-FF as health indicator
    pct = non_ff * 100 // FW_SIZE
    if pct > 50:
        result['healthy'] = True
        result['detail'] = f'intact ({pct}% programmed)'
    elif pct > 10:
        result['healthy'] = True
        result['detail'] = f'partial ({pct}% programmed)'
    else:
        result['detail'] = f'sparse ({pct}% programmed)'

    return result


def _check_header(data):
    """Analyze SNVS header at 0x60000-0x6000F."""
    result = {'healthy': False, 'first_16': b'', 'has_markers': False, 'detail': ''}
    if len(data) < SNVS_OFF + 16:
        result['detail'] = 'data too small'
        return result

    hdr = data[SNVS_OFF:SNVS_OFF + 16]
    result['first_16'] = hdr
    has_a5 = hdr[0] == 0xA5
    has_c3 = hdr[7] == 0xC3 and hdr[15] == 0xC3
    result['has_markers'] = has_a5 and has_c3

    if hdr[0] == 0xA5 and hdr[7] == 0xC3:
        result['healthy'] = True
        result['detail'] = 'valid entry markers'
    elif hdr[0] == 0xA5 and hdr[7] != 0xC3:
        result['detail'] = 'partial corruption (missing C3)'
    elif hdr[0] != 0xA5 and hdr[7] == 0xC3:
        result['detail'] = 'partial corruption (missing A5)'
    elif all(b == 0xFF for b in hdr):
        result['detail'] = 'all FF (erased)'
    elif all(b == 0x00 for b in hdr):
        result['detail'] = 'all 00 (blank)'
    else:
        result['detail'] = 'corrupted'
    return result


def _check_flatdata(data, valid_entries):
    """Analyze flatdata area (0x60800-0x60C00)."""
    result = {'healthy': False, 'ff_percent': 0, 'entries_match': False, 'detail': ''}
    if len(data) < AREA0_FLAT + FLAT_SIZE:
        result['detail'] = 'data too small'
        return result

    fd_area = data[AREA0_FLAT:AREA0_FLAT + FLAT_SIZE]
    ff_count = sum(1 for b in fd_area if b == 0xFF)
    ff_pct = ff_count * 100 // FLAT_SIZE
    result['ff_percent'] = ff_pct

    # Check flatdata matches entries
    entries_with_data = sum(1 for e in valid_entries if any(b != 0x00 for b in e['data']))
    if entries_with_data == 0:
        result['entries_match'] = False
        if ff_pct > 90:
            result['detail'] = f'all FF ({ff_pct}%) — erased'
        else:
            result['detail'] = f'{ff_pct}% FF, entries have data — possible mismatch'
        return result

    # Count slots that have actual data (non-FF, non-00)
    used_slots = 0
    for typ in range(128):
        off = typ * 8
        if off + 8 > FLAT_SIZE:
            break
        slot = fd_area[off:off + 8]
        if any(b not in (0x00, 0xFF) for b in slot):
            used_slots += 1

    if used_slots >= 3:
        result['healthy'] = True
        if ff_pct < 80:
            result['entries_match'] = True
        result['detail'] = f'intact ({used_slots} slots used, {ff_pct}% FF)'
    elif used_slots > 0:
        result['detail'] = f'partial ({used_slots} slots used, {ff_pct}% FF)'
    else:
        result['detail'] = f'empty ({ff_pct}% FF)'
    return result


def _check_entries(data):
    """Analyze SNVS entries across all areas."""
    result = {'total': 0, 'valid': 0, 'invalid': 0, 'unique_types': 0,
              'missing_types': [], 'has_counter_anomalies': False,
              'has_preserved_areas': False, 'detail': ''}

    all_entries = _scan_entries(data, max_area=7)
    result['total'] = len(all_entries)
    result['valid'] = len(all_entries)

    unique_types = set()
    type_counters = {}
    for e in all_entries:
        unique_types.add(e['type'])
        if e['type'] not in type_counters or e['counter'] > type_counters[e['type']]:
            type_counters[e['type']] = e['counter']

    result['unique_types'] = len(unique_types)

    # Check for missing core types (0x00-0x0B)
    expected_core = set(range(0x00, 0x0C))
    missing_core = expected_core - unique_types
    result['missing_types'] = sorted(missing_core)

    # Check for counter anomalies
    if type_counters:
        counters = list(type_counters.values())
        max_c = max(counters)
        min_c = min(counters)
        if max_c - min_c > 0xFFFFFF:
            result['has_counter_anomalies'] = True

    # Check preserved areas (8+) — only areas beyond the 0-7 range
    preserved_area_8 = SNVS_OFF + 0x800 + 8 * AREA_SIZE
    if len(data) > preserved_area_8:
        preserved_extra = _scan_entries(data, max_area=15)
        preserved_extra = [e for e in preserved_extra if e['offset'] >= preserved_area_8]
    else:
        preserved_extra = []
    result['has_preserved_areas'] = len(preserved_extra) > 0

    # Build detail
    parts = [f'{result["valid"]} valid entries, {result["unique_types"]} types']
    if result['missing_types']:
        parts.append(f'missing types: {", ".join(f"0x{t:02x}" for t in result["missing_types"][:6])}')
        if len(result['missing_types']) > 6:
            parts[-1] += f'... ({len(result["missing_types"])} total)'
    if result['has_counter_anomalies']:
        parts.append('counter anomalies detected')
    if result['has_preserved_areas']:
        parts.append(f'has {len(preserved_extra)} entries in preserved areas')
    result['detail'] = '; '.join(parts)

    return result


def _check_preserved_areas(data):
    """Analyze preserved areas (8+) for useful data."""
    result = {'healthy': False, 'valid_entries': 0,
              'has_preserved_fw_records': False, 'detail': ''}

    area8_start = SNVS_OFF + 0x800 + 8 * AREA_SIZE
    if len(data) < area8_start + 0x400:
        result['detail'] = 'no preserved areas'
        return result

    preserved = _scan_entries(data, max_area=15)
    area8plus = [e for e in preserved if e['offset'] >= area8_start]
    result['valid_entries'] = len(area8plus)

    # Check for preserved FW record types (0x28-0x2B)
    fw_types = set(range(0x28, 0x2C))
    preserved_fw_types = [e for e in area8plus if e['type'] in fw_types]
    result['has_preserved_fw_records'] = len(preserved_fw_types) > 0

    if result['valid_entries'] > 20:
        result['healthy'] = True
        result['detail'] = f'{result["valid_entries"]} entries preserved'
    elif result['valid_entries'] > 0:
        result['detail'] = f'{result["valid_entries"]} entries found'

    return result


def analyze_syscon(syscon_data, nor_data=None):
    """
    Comprehensive syscon damage analysis.
    
    Args:
        syscon_data: Raw syscon dump bytes
        nor_data: Optional NOR dump for ARV lookup
    
    Returns:
        DamageReport with full analysis
    """
    report = DamageReport()
    size = len(syscon_data)
    if size not in VALID_SIZES:
        report.severity = 'critical'
        report.summary = f'Invalid size: {size} bytes (expected 256KB or 512KB)'
        report.recommendation = 4
        return report

    # Run all checks
    report.firmware = _check_firmware(syscon_data)
    report.snvs_header = _check_header(syscon_data)
    all_entries = _scan_entries(syscon_data, max_area=7)
    report.flatdata = _check_flatdata(syscon_data, all_entries)
    report.entries = _check_entries(syscon_data)
    report.preserved_areas = _check_preserved_areas(syscon_data)

    # Determine damage type and severity
    fw_healthy = report.firmware['healthy']
    hdr_healthy = report.snvs_header['healthy']
    fd_healthy = report.flatdata['healthy']
    ent_valid = report.entries['valid']
    ent_missing = report.entries['missing_types']

    # Classify damage type
    if not fw_healthy and ent_valid < 5:
        report.damage_type = 'full'
    elif not fw_healthy:
        report.damage_type = 'firmware_corrupted'
    elif ent_valid < 5:
        report.damage_type = 'snvs_erased'
    elif len(ent_missing) > 6:
        report.damage_type = 'snvs_severe'
    elif len(ent_missing) > 0:
        report.damage_type = 'snvs_partial'
    elif not hdr_healthy:
        report.damage_type = 'header_corrupted'
    elif not fd_healthy:
        report.damage_type = 'flatdata_corrupted'
    else:
        report.damage_type = 'none'

    # Set severity
    if report.damage_type == 'full':
        report.severity = 'critical'
    elif report.damage_type == 'firmware_corrupted':
        report.severity = 'critical'
    elif report.damage_type == 'snvs_erased':
        report.severity = 'severe'
    elif report.damage_type == 'snvs_severe':
        report.severity = 'moderate'
    elif report.damage_type == 'snvs_partial':
        report.severity = 'minor'
    elif report.damage_type in ('header_corrupted', 'flatdata_corrupted'):
        report.severity = 'minor'
    else:
        report.severity = 'none'

    # Auto-select repair level
    if report.damage_type == 'none':
        report.recommendation = 0
    elif report.damage_type in ('header_corrupted', 'flatdata_corrupted'):
        report.recommendation = 1
    elif report.damage_type == 'snvs_partial':
        report.recommendation = 2
    elif report.damage_type == 'snvs_severe':
        report.recommendation = 2
    elif report.damage_type == 'snvs_erased':
        report.recommendation = 3
    elif report.damage_type == 'firmware_corrupted':
        report.recommendation = 4
    elif report.damage_type == 'full':
        report.recommendation = 4

    # Summary
    if report.damage_type == 'none':
        report.summary = 'Syscon appears healthy'
    elif report.damage_type == 'header_corrupted':
        report.summary = f'Minor: header corruption at 0x60000'
    elif report.damage_type == 'flatdata_corrupted':
        report.summary = 'Minor: flatdata mismatch'
    elif report.damage_type == 'snvs_partial':
        report.summary = f'Moderate: {len(ent_missing)} core types missing in SNVS'
    elif report.damage_type == 'snvs_severe':
        report.summary = f'Severe: SNVS has only {len(ent_missing)}/12 core types'
    elif report.damage_type == 'snvs_erased':
        report.summary = 'Severe: SNVS erased or unreadable'
    elif report.damage_type == 'firmware_corrupted':
        report.summary = f'Critical: firmware area damaged ({report.firmware["detail"]})'
    elif report.damage_type == 'full':
        report.summary = 'Critical: full corruption (firmware + SNVS)'

    return report


def format_analysis_report(report):
    """Format DamageReport as human-readable string."""
    lines = []
    lines.append('=' * 58)
    lines.append('  SYSCON DAMAGE ANALYSIS')
    lines.append('=' * 58)
    
    severity_colors = {
        'none': 'OK',
        'minor': 'MINOR',
        'moderate': 'MODERATE',
        'severe': 'SEVERE',
        'critical': 'CRITICAL',
    }
    lines.append(f'  Severity:       {severity_colors.get(report.severity, report.severity)}')
    lines.append(f'  Damage Type:    {report.damage_type}')
    lines.append(f'  Recommendation: {report.recommendation}')
    lines.append(f'  Summary:        {report.summary}')
    lines.append('')
    lines.append(f'  --- Firmware Area (0x000-0x5FFFF) ---')
    lines.append(f'  Healthy:        {report.firmware["healthy"]}')
    lines.append(f'  Non-FF bytes:   {report.firmware["non_ff"]:,}')
    lines.append(f'  Has Vectors:    {report.firmware["has_vectors"]}')
    lines.append(f'  Detail:         {report.firmware["detail"]}')
    lines.append('')
    lines.append(f'  --- SNVS Header (0x60000-0x6000F) ---')
    lines.append(f'  Healthy:        {report.snvs_header["healthy"]}')
    lines.append(f'  Detail:         {report.snvs_header["detail"]}')
    if report.snvs_header['first_16']:
        hx = ' '.join(f'{b:02X}' for b in report.snvs_header['first_16'])
        lines.append(f'  First 16:       {hx}')
    lines.append('')
    lines.append(f'  --- Flatdata (0x60800-0x60BFF) ---')
    lines.append(f'  Healthy:        {report.flatdata["healthy"]}')
    lines.append(f'  FF filled:      {report.flatdata["ff_percent"]}%')
    lines.append(f'  Detail:         {report.flatdata["detail"]}')
    lines.append('')
    lines.append(f'  --- Entries ---')
    lines.append(f'  Valid entries:  {report.entries["valid"]}')
    lines.append(f'  Unique types:   {report.entries["unique_types"]}')
    if report.entries['missing_types']:
        mt = ', '.join(f'0x{t:02X}' for t in report.entries['missing_types'])
        lines.append(f'  Missing types:  {mt}')
    if report.entries['has_counter_anomalies']:
        lines.append(f'  Counter issues: yes')
    lines.append(f'  Detail:         {report.entries["detail"]}')
    lines.append('')
    lines.append(f'  --- Preserved Areas (8+) ---')
    lines.append(f'  Healthy:        {report.preserved_areas["healthy"]}')
    lines.append(f'  Entries found:  {report.preserved_areas["valid_entries"]}')
    lines.append(f'  Detail:         {report.preserved_areas["detail"]}')
    lines.append('=' * 58)
    return '\n'.join(lines)


REPAIR_LEVELS = {
    0: 'No repair needed',
    1: 'Light Repair — fix header and flatdata',
    2: 'Medium Repair — WeeTools Rebuild (keep FW, regenerate SNVS)',
    3: 'Heavy Repair — Full SNVS Regeneration with ARV',
    4: 'Full Repair — Donor firmware + SNVS Regeneration',
}
