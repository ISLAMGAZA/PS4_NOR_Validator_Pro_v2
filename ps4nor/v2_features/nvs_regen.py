"""
NVS Regeneration Module — 3 methods per WeeTools PRO approach.
Method 1 (Accurate Bytes): copy safe config, preserve identity
Method 2 (Blind Copy):     copy last half of NVS from donor
Method 3 (Combined):       Method 1 + Method 2
"""

from ..utils.nor_defs import NVS_START, NVS_END, NVS_IDENTITY_RANGES, BOARD_ID_OFFSET, BOARD_ID_SIZE


def extract_board_id(data):
    """Extract 8-byte Board ID from NVS_START (0x1C4000)."""
    if len(data) < BOARD_ID_OFFSET + BOARD_ID_SIZE:
        return None
    return bytes(data[BOARD_ID_OFFSET:BOARD_ID_OFFSET + BOARD_ID_SIZE])


def format_board_id(board_id):
    """Format Board ID bytes to string like '03:02:02:01:01:01:05:01'."""
    if not board_id or len(board_id) < 8:
        return 'Unknown'
    return ':'.join('%02X' % b for b in board_id[:8])


def board_id_match_level(bid_orig, bid_donor):
    """Compare two Board IDs, return match level:
    0 = exact match (identical all 8 bytes)
    1 = close match (byte 2 differs, rest same — same family)
    2 = different (bytes differ beyond byte 2)
    """
    if not bid_orig or not bid_donor or len(bid_orig) < 8 or len(bid_donor) < 8:
        return 2
    if bid_orig == bid_donor:
        return 0
    # Compare bytes: 0,1 should be 03:02 (Sony PS4), 3-4 should be 01:01
    if (bid_orig[0] == bid_donor[0] == 0x03 and
        bid_orig[1] == bid_donor[1] == 0x02 and
        bid_orig[3:5] == bid_donor[3:5] and
        bid_orig[5:] == bid_donor[5:]):
        return 1
    return 2


def _restore_identity_ranges(result, original, donor):
    """Restore NVS identity ranges from original, fallback to donor.
    'result' must be either full 32MB dump or NVS sub-buffer (48KB).
    Returns bytearray (mutates in place if already bytearray)."""
    if isinstance(result, bytes):
        result = bytearray(result)
    is_full = len(result) > 0x10000  # full dump vs NVS sub-buffer
    for start, end in NVS_IDENTITY_RANGES:
        chunk = original[start:end]
        if sum(1 for b in chunk if b not in (0, 0xFF)) > 4:
            if is_full:
                result[start:end] = chunk
            else:
                lo = NVS_START
                result[start - lo:end - lo] = chunk
        elif donor is not None:
            if is_full:
                result[start:end] = donor[start:end]
            else:
                lo = NVS_START
                result[start - lo:end - lo] = donor[start:end]
    return result


def _is_identity_range(offset):
    """Check if an absolute NOR offset falls within any identity range."""
    for start, end in NVS_IDENTITY_RANGES:
        if start <= offset < end:
            return True
    return False


def nvs_regen_method1(target_data, donor_data):
    """Method 1: Accurate Bytes — copy safe config from donor,
    preserve all identity ranges from target.

    Returns (regen_data, report_lines)
    """
    report = []
    t = bytearray(target_data)
    d = donor_data
    lo, hi = NVS_START, NVS_END

    # Start with a copy of target NVS
    nvs = bytearray(t[lo:hi])

    # Copy non-identity regions from donor
    copied = 0
    skipped = 0
    for off in range(lo, hi):
        idx = off - lo
        if _is_identity_range(off):
            skipped += 1
        else:
            # Copy donor byte if donor has it
            if off < len(d):
                nvs[idx] = d[off]
                copied += 1

    # Restore identity ranges from target
    nvs = bytearray(_restore_identity_ranges(nvs, t, d))

    # Apply to result
    result = bytearray(target_data)
    result[lo:hi] = nvs

    report.append(f"  NVS Regeneration Method 1 (Accurate Bytes):")
    report.append(f"    Copied {copied} config bytes from donor")
    report.append(f"    Preserved {skipped} identity bytes from target")

    return bytes(result), report


def nvs_regen_method2(target_data, donor_data):
    """Method 2: Blind Copy — copy last half of NVS (0x1C8000+) from donor,
    then restore identity ranges from target.

    Returns (regen_data, report_lines)
    """
    report = []
    t = bytearray(target_data)
    d = donor_data
    lo, hi = NVS_START, NVS_END
    mid = lo + (hi - lo) // 2  # 0x1C8000

    result = bytearray(target_data)
    # Copy all of NVS from donor as base
    if len(d) >= hi:
        result[lo:hi] = d[lo:hi]
    # Restore identity from target
    result = bytearray(_restore_identity_ranges(bytes(result), t, d))

    report.append(f"  NVS Regeneration Method 2 (Blind Copy):")
    report.append(f"    Copied {hex(mid)}-{hex(hi)} from donor (last half)")
    report.append(f"    Preserved identity from target")

    return bytes(result), report


def nvs_regen_method3(target_data, donor_data):
    """Method 3: Combined — Method 1 first, then Method 2 override on top.

    Returns (regen_data, report_lines)
    """
    report = []
    report.append(f"  NVS Regeneration Method 3 (Combined 1+2):")

    # Step 1: Method 1 (accurate bytes)
    m1_result, m1_report = nvs_regen_method1(target_data, donor_data)
    for line in m1_report:
        report.append(f"  {line}")

    # Step 2: Override with Method 2 (blind copy of last half)
    lo, hi = NVS_START, NVS_END
    mid = lo + (hi - lo) // 2
    donor_nvs = donor_data[mid:hi]
    result = bytearray(m1_result)
    result[mid:hi] = donor_nvs
    # Restore identity again
    result = bytearray(_restore_identity_ranges(bytes(result), bytearray(target_data), donor_data))

    report.append(f"    Then overlaid {hex(mid)}-{hex(hi)} from donor (Method 2)")
    report.append(f"    Final identity preserved")

    return bytes(result), report


def nvs_regen_auto(target_data, donor_data):
    """Auto-select best method based on Board ID match level.
    0 (exact) -> Method 3 (full rebuild)
    1 (close) -> Method 1 (safe)
    2 (diff)  -> Method 1 (safe, conservative)
    """
    bid_orig = extract_board_id(target_data)
    bid_donor = extract_board_id(donor_data)
    level = board_id_match_level(bid_orig, bid_donor)

    if level == 0:
        return nvs_regen_method3(target_data, donor_data)
    else:
        return nvs_regen_method1(target_data, donor_data)


def nvs_regen_interactive(target_data, donor_data, donor_name='donor'):
    """Interactive NVS regeneration: show Board ID comparison, let user pick method."""
    from ..utils.colors import ok, warn, info, dim, value, fail

    bid_orig = extract_board_id(target_data)
    bid_donor = extract_board_id(donor_data)

    bid_orig_str = format_board_id(bid_orig)
    bid_donor_str = format_board_id(bid_donor)
    level = board_id_match_level(bid_orig, bid_donor) if (bid_orig and bid_donor) else 2

    level_str = {0: ok('EXACT MATCH'), 1: warn('CLOSE MATCH'), 2: dim('DIFFERENT')}.get(level, dim('UNKNOWN'))

    print()
    print(f'  {info("NVS Regeneration — Board ID Comparison:")}')
    print(f'    Target Board ID:  {value(bid_orig_str)}')
    print(f'    Donor Board ID:   {value(bid_donor_str)}  ({donor_name})')
    print(f'    Match level:      {level_str}')

    if level == 0:
        print(f'    {ok("Board IDs match exactly — full NVS rebuild is safe")}')
    elif level == 1:
        print(f'    {warn("Board IDs differ (motherboard variant) — safe copy recommended")}')
    else:
        print(f'    {dim("Board IDs differ — conservative copy only")}')

    print()
    print(f'  {info("Select NVS Regeneration Method:")}')
    print(f'    {dim("[1]")} Method 1 (Accurate Bytes) — Copy safe config, preserve identity')
    print(f'    {dim("[2]")} Method 2 (Blind Copy) — Copy last half of NVS from donor')
    print(f'    {dim("[3]")} Method 3 (Combined 1+2) — Most aggressive rebuild')
    print(f'    {dim("[S]")} Skip NVS regeneration')

    choice = input(f'  {info("Choice")} (1/2/3/S): ').strip().lower()

    if choice == '1':
        result, report = nvs_regen_method1(target_data, donor_data)
    elif choice == '2':
        result, report = nvs_regen_method2(target_data, donor_data)
    elif choice == '3':
        result, report = nvs_regen_method3(target_data, donor_data)
    else:
        print(f'  {dim("NVS regeneration skipped.")}')
        return target_data, ['NVS regeneration skipped']

    for line in report:
        print(f'  {line}')
    print(f'  {ok("NVS regeneration complete.")}')

    return result, report
