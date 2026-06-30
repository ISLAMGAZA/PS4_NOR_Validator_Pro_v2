"""
Hybrid Repair Engine v2.1
Four-pass repair pipeline:
  Pass 1 — FW Blob (exact MD5 match / FW range + type code)
  Pass 2 — Smart Donor (same FW version only)
  Pass 3 — Cross-Donor Cascade (current v2 fallback)
  Pass 4 — Byte-Level Patching (replace only corrupt bytes)
"""

import os
import re

from ..utils.helpers import md5_hash, detect_sku, detect_fw_version, is_all_zeros, is_all_ff
from ..utils.fw_db import detect_southbridge
from ..utils.colors import C, ok, fail, warn, info, title, brand, dim, value, hr
from ..utils.nor_defs import NVS_IDENTITY_RANGES
from ..patchers.auto_repair import AutoRepair, _region_healthy
from .smart_donor import SmartDonorMatcher

SECTION_MAP = {
    'EMC_IPL_A': ('emc', 0x004000, 0x064000, 0x60000),
    'EMC_IPL_B': ('emc', 0x064000, 0x0C4000, 0x60000),
    'EAP_KBL':   ('eap', 0x0C4000, 0x144000, 0x80000),
    'Torus':     ('torus', 0x144000, 0x1C4000, 0x80000),
}


def _fw_version_to_int(fw_str):
    """Convert '10.50' -> 1050"""
    if not fw_str or fw_str == 'Unknown':
        return None
    fw_str = fw_str.split('<')[0].split('\u2192')[0].split('-')[0].strip()
    parts = fw_str.split('.')
    try:
        major = int(parts[0])
        minor = int(parts[1][:2]) if len(parts) > 1 else 0
        return major * 100 + minor
    except (ValueError, IndexError):
        return None


def _parse_blob_filename(filename):
    """Parse '1050-1304_md5.2bls' -> (min_fw, max_fw, md5) or None"""
    m = re.match(r'^(\d{4})-(\d{4})_([a-fA-F0-9]{32})\.2bls$', filename)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), m.group(3).lower()


def _make_matcher(donors_dir):
    matcher = SmartDonorMatcher(donors_dir, use_cache=False)
    matcher.WEIGHTS = dict(matcher.WEIGHTS)
    matcher.WEIGHTS['fw'] = 30.0
    matcher.WEIGHTS['series'] = 25.0
    matcher.WEIGHTS['model'] = 20.0
    return matcher


def _match_fw_range(blob_min, blob_max, target_fw_int):
    """Check if target FW is within blob range"""
    return blob_min <= target_fw_int <= blob_max


class HybridRepairV21:
    def __init__(self, data, fws_dir='fws', donors_dir='donors'):
        self.original = bytes(data)
        self.data = bytearray(data)
        self.fws_dir = fws_dir
        self.donors_dir = donors_dir
        self.report_lines = []
        self.repair_count = 0
        self.skipped_count = 0
        self.donor_data = None
        self.donor_path = None

    def _log(self, msg):
        self.report_lines.append(msg)

    def _colorize_log(self, msg):
        self._log(self._colorize(msg))

    def _colorize(self, msg):
        if msg.startswith('=== '):
            return title(msg)
        if msg.startswith('--- '):
            return info(msg)
        msg = re.sub(r'(?<=: )(OK)$', lambda m: ok(m.group(1)), msg)
        msg = re.sub(r'(?<=: )(REPAIRED)\b', lambda m: ok(m.group(1)), msg)
        msg = re.sub(r'(?<=: )(SYNCED)\b', lambda m: ok(m.group(1)), msg)
        msg = re.sub(r'(?<=: )(FAILED)\b', lambda m: fail(m.group(1)), msg)
        msg = re.sub(r'(score=)([\d.]+)', lambda m: m.group(1) + value(m.group(2)), msg)
        msg = re.sub(r'(SKU=)(\S+)', lambda m: m.group(1) + value(m.group(2)), msg)
        msg = re.sub(r'(FW=)(\S+)', lambda m: m.group(1) + value(m.group(2)), msg)
        msg = re.sub(r'(Blob: )(\S+)', lambda m: m.group(1) + value(m.group(2)), msg)
        msg = re.sub(r'(Donor: )(\S+)', lambda m: m.group(1) + value(m.group(2)), msg)
        msg = re.sub(r'(0x[0-9A-Fa-f]{4,8})', lambda m: value(m.group(1)), msg)
        return msg

    # ── Pass 1: FW Blob ──────────────────────────────────────

    def _find_blob(self, section_name, fw_int, type_code):
        """Find best matching .2bls file for section by FW range + type code"""
        info = SECTION_MAP.get(section_name)
        if not info:
            return None
        sub_dir, start, end, size = info
        fw_dir = os.path.join(self.fws_dir, sub_dir)
        type_dir = os.path.join(fw_dir, f'{type_code:02X}')
        if not os.path.isdir(type_dir):
            return None

        best_blob = None
        best_range = None
        for fname in sorted(os.listdir(type_dir)):
            if not fname.endswith('.2bls'):
                continue
            parsed = _parse_blob_filename(fname)
            if not parsed:
                continue
            blob_min, blob_max, blob_md5 = parsed
            if blob_min <= fw_int <= blob_max:
                if best_blob is None or (blob_max - blob_min) < (best_range[1] - best_range[0]):
                    best_blob = fname
                    best_range = (blob_min, blob_max)

        if best_blob:
            path = os.path.join(type_dir, best_blob)
            try:
                with open(path, 'rb') as f:
                    blob_data = f.read()
                return blob_data, best_blob
            except Exception:
                return None
        return None

    def _pass1_fw_blob(self):
        self._log('')
        self._log('--- Pass 1: FW Blob Repair ---')
        target_fw = detect_fw_version(bytes(self.data))
        fw_int = _fw_version_to_int(target_fw)
        if not fw_int:
            self._log(f'  Cannot determine FW version — skipping blob pass')
            return False

        # Detect southbridge for type codes
        emc_a_md5 = md5_hash(bytes(self.data[0x004000:0x064000])).lower()
        eap_md5 = md5_hash(bytes(self.data[0x0C4000:0x144000])).lower()
        sb = detect_southbridge(emc_a_md5, eap_md5)
        emc_type = sb['code'][0] if sb['code'] else None
        eap_type = sb['code'][1] if len(sb['code']) > 1 else None

        if not os.path.isdir(self.fws_dir):
            self._log(f'  {warn("fws/ directory not found — skipping blob pass")}')
            return False

        self._log(f'  Target FW: {value(target_fw)} ({fw_int})')
        self._log(f'  Southbridge: {value(sb.get("name", "Unknown"))} type={value(f"{emc_type:02X}/{eap_type:02X}") if emc_type else "N/A"}')

        any_repaired = False
        for section_name, (sub_dir, start, end, sec_size) in SECTION_MAP.items():
            if section_name.startswith('EMC_IPL'):
                type_code = emc_type
                from ..utils.fw_db import EMC_IPL_MD5 as fw_db
            elif section_name == 'EAP_KBL':
                type_code = eap_type
                from ..utils.fw_db import EAP_KBL_MD5 as fw_db
            elif section_name == 'Torus':
                from ..utils.fw_db import TORUS_FW_MD5 as fw_db
                torus_md5 = md5_hash(bytes(self.data[0x144000:0x1C4000])).lower()
                t_info = fw_db.get(torus_md5)
                type_code = t_info['t'] if t_info else emc_type
            else:
                type_code = emc_type
                fw_db = None
            if type_code is None:
                continue
            section_md5 = md5_hash(bytes(self.data[start:end])).lower()
            md5_known = fw_db is not None and section_md5 in fw_db
            needs_repair = not md5_known or not _region_healthy(self.data, start, end)
            blob = self._find_blob(section_name, fw_int, type_code)
            if blob:
                if not needs_repair:
                    self._colorize_log(f'  {section_name} ({hex(start)}): OK (known MD5, skipped)')
                else:
                    blob_data, blob_name = blob
                    blob_trimmed = blob_data[:sec_size] if len(blob_data) >= sec_size else blob_data.ljust(sec_size, b'\xFF')
                    self.data[start:start+sec_size] = blob_trimmed
                    if not _region_healthy(self.data, start, end):
                        self._colorize_log(f'  {section_name} ({hex(start)}): REPAIRED from blob {blob_name}')
                    else:
                        self._colorize_log(f'  {section_name} ({hex(start)}): REPLACED (unknown MD5) with blob {blob_name}')
                    self.repair_count += 1
                    any_repaired = True
            else:
                self._colorize_log(f'  {section_name}: no matching blob for FW {target_fw}')

        return any_repaired

    # ── Pass 2: Same-FW Donor ───────────────────────────────

    def _pass2_same_fw_donor(self):
        self._log('')
        self._log('--- Pass 2: Same-FW Donor Repair ---')
        target_sku = detect_sku(bytes(self.data))
        target_fw = detect_fw_version(bytes(self.data))
        if not os.path.isdir(self.donors_dir):
            self._log(f'  No donors directory — skipping pass 2')
            return False
        matcher = _make_matcher(self.donors_dir)
        result = matcher.match(target_sku, target_fw)
        best = result.best

        # Force same FW if available (compare numeric, not string — target_fw may be '10.50 <-> 13.52')
        target_fw_int = _fw_version_to_int(target_fw)
        same_fw = []
        for d in result.matches:
            if d.score <= 0:
                continue
            d_fw_int = _fw_version_to_int(d.fw_version)
            if d_fw_int and target_fw_int and d_fw_int == target_fw_int:
                same_fw.append(d)
        if same_fw:
            best = max(same_fw, key=lambda d: d.score)
            self._log(f'  Filtered to same-FW donors: {value(str(len(same_fw)))} candidates')
        elif best:
            self._log(f'  No exact FW match — best donor: {value(best.filename)} (FW={best.fw_version})')

        if not best:
            self._log(f'  No suitable donor found — skipping pass 2')
            return False

        try:
            with open(best.filepath, 'rb') as f:
                self.donor_data = f.read()
                self.donor_path = best.filepath
        except Exception as e:
            self._log(f'  Error loading donor: {e}')
            return False

        self._colorize_log(f'  Donor: {best.filename} (score={best.score} SKU={best.sku} FW={best.fw_version})')

        # Repair sections that are still damaged after pass 1
        repaired_any = False
        for section_name, (sub_dir, start, end, sec_size) in SECTION_MAP.items():
            if _region_healthy(self.data, start, end):
                continue
            donor_chunk = self.donor_data[start:start+sec_size]
            if is_all_zeros(donor_chunk) or is_all_ff(donor_chunk):
                continue
            self.data[start:start+sec_size] = donor_chunk
            self._colorize_log(f'  {section_name}: REPAIRED from same-FW donor')
            self.repair_count += 1
            repaired_any = True

        return repaired_any

    # ── Pass 3: Cross-Donor Cascade ──────────────────────────

    def _pass3_cross_donor(self):
        self._log('')
        self._log('--- Pass 3: Cross-Donor Cascade ---')
        repaired_any = False
        if self.donor_data:
            donor_loaded = True
        else:
            donor_loaded = False
            if os.path.isdir(self.donors_dir):
                target_sku = detect_sku(bytes(self.data))
                target_fw = detect_fw_version(bytes(self.data))
                matcher = _make_matcher(self.donors_dir)
                result = matcher.match(target_sku, target_fw)
                if result.best:
                    try:
                        with open(result.best.filepath, 'rb') as f:
                            self.donor_data = f.read()
                            self.donor_path = result.best.filepath
                            donor_loaded = True
                    except Exception:
                        pass

        if donor_loaded:
            for section_name, (sub_dir, start, end, sec_size) in SECTION_MAP.items():
                if _region_healthy(self.data, start, end):
                    continue
                chunk = self.donor_data[start:start+sec_size]
                if is_all_zeros(chunk) or is_all_ff(chunk):
                    continue
                self.data[start:start+sec_size] = chunk
                self._colorize_log(f'  {section_name}: REPAIRED from cross-donor')
                self.repair_count += 1
                repaired_any = True
        else:
            self._log(f'  No donor loaded — skipping pass 3')

        return repaired_any

    # ── Pass 4: Byte-Level Patching (FW-excluded) ────────────

    FW_RANGES = [(0x4000, 0xC4000), (0x0C4000, 0x144000), (0x144000, 0x1C4000)]  # EMC_IPL + EAP_KBL + Torus
    # EAP HDD key blobs — must NOT be modified by byte patching (0x40 vs 0x60 key size)
    EAP_KEY_RANGES = [(0x1C91FC, 0x1C9260), (0x1CC1FC, 0x1CC260)]

    def _in_fw_range(self, offset):
        for fs, fe in self.FW_RANGES:
            if fs <= offset < fe:
                return True
        return False

    def _in_eap_key_range(self, offset):
        for rs, re in self.EAP_KEY_RANGES:
            if rs <= offset < re:
                return True
        return False

    def _in_identity_range(self, offset):
        for rs, re in NVS_IDENTITY_RANGES:
            if rs <= offset < re:
                return True
        return False

    def _warn_fw_mismatch(self):
        if self.donor_data is None:
            return
        target_fw = detect_fw_version(bytes(self.original))
        if not target_fw or target_fw == 'Unknown':
            return
        donor_fw = detect_fw_version(self.donor_data)
        if not donor_fw or donor_fw == 'Unknown':
            return
        if target_fw != donor_fw:
            self._log(warn(f'  ? WARNING: Donor FW ({donor_fw}) != Target FW ({target_fw})'))
            self._log(dim('    Identity regions (Board ID, MAC, Serial, CID) protected.'))

    def _pass4_byte_level(self):
        self._log('')
        self._log('--- Pass 4: Byte-Level Patching (NVS/CID only) ---')
        if self.donor_data is None:
            self._log(f'  No donor data — skipping byte-level patching')
            return False

        patched_bytes = 0
        for start in range(0, len(self.data), 0x1000):
            if self._in_fw_range(start):
                continue
            end = min(start + 0x1000, len(self.data))
            orig_chunk = self.original[start:end]
            donor_chunk = self.donor_data[start:end]
            for i in range(len(orig_chunk)):
                abs_off = start + i
                if abs_off >= len(self.data):
                    break
                if self._in_eap_key_range(abs_off):
                    continue
                if self._in_identity_range(abs_off):
                    continue
                orig_byte = orig_chunk[i]
                donor_byte = donor_chunk[i] if i < len(donor_chunk) else 0xFF
                current_byte = self.data[abs_off]
                # Replace if:
                # 1. Current byte is 0x00/0xFF (corrupt) AND
                # 2. Donor byte is NOT 0x00/0xFF (valid)
                # 3. Original byte at repair time was also corrupt
                if current_byte in (0x00, 0xFF) and donor_byte not in (0x00, 0xFF):
                    self.data[abs_off] = donor_byte
                    patched_bytes += 1

        if patched_bytes:
            self._colorize_log(f'  Patched {value(str(patched_bytes))} corrupted bytes from donor')
            self.repair_count += 1
            return True
        else:
            self._log(f'  No corrupt bytes to patch')
            return False

    # ── Non-FW sections: delegate to AutoRepair ──────────────

    def _repair_non_fw(self):
        self._log('')
        self._log('--- Non-FW Sections (AutoRepair) ---')
        # Wrap in AutoRepair for NVS, CID, MBR, SCE header, etc.
        repair = AutoRepair(bytes(self.data), self.donors_dir, self.fws_dir)
        # Transfer donor if we already loaded one
        if self.donor_data:
            repair.donor_data = self.donor_data
            repair.donor_path = self.donor_path

        applied = repair.repair_all(fix_warnings=True)
        self.data = bytearray(repair.get_data())
        sub_report = repair.get_report()
        for line in sub_report.split('\n'):
            self._log(f'  {line}')
        if applied:
            self.repair_count += repair.repair_count
            self.skipped_count += repair.skipped_count

    # ── Main entry ───────────────────────────────────────────

    def repair_all(self):
        self.report_lines = []
        self.repair_count = 0
        self.skipped_count = 0

        self._colorize_log('=== Hybrid Auto-Repair v2.1 ===')
        self._colorize_log(f'FWS: {value(self.fws_dir)}  Donors: {value(self.donors_dir)}')

        self._pass1_fw_blob()
        self._pass2_same_fw_donor()
        self._pass3_cross_donor()
        self._warn_fw_mismatch()
        self._pass4_byte_level()
        self._repair_non_fw()

        self._log('')
        total = self.repair_count + self.skipped_count
        if total == 0:
            self._colorize_log('No issues found — dump is healthy')
        else:
            self._colorize_log(f'Repairs applied: {value(str(self.repair_count))}, Skipped: {value(str(self.skipped_count))}')

        return self.repair_count > 0

    def get_data(self):
        return bytes(self.data)

    def get_report(self):
        return '\n'.join(self.report_lines)







