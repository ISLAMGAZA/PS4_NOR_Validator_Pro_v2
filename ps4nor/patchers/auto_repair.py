import os
import re
from ..utils.helpers import md5_hash, is_all_zeros, is_all_ff, detect_sku, detect_fw_version, decode_nvs_fw
from ..utils.nor_defs import NOR_LAYOUT, CID_REGIONS, UART_OFFSET
from ..utils.fw_db import EMC_IPL_MD5, EAP_KBL_MD5, TORUS_FW_MD5, detect_southbridge
from ..donors.repair_engine import RepairEngine
from .mbr_generator import MBRGenerator, _parse_mbr, MBR1_OFF, MBR2_OFF, MBR_SIZE
from .nvs_generator import NVSGenerator
from ..v2_features.smart_donor import SmartDonorMatcher
from ..utils.colors import C, ok, fail, warn, info, title, brand, dim, value

# NVS sub-region offsets (absolute NOR)
NVS_START = 0x1C4000
SN_ABS_OFFSET = 0x1C8030
FW_VER_ABS_OFFSET = 0x1C906A
CID_1CA = 0x1CA000
CID_1CD = 0x1CD000
CID_1C9 = 0x1C9000
CID_1CC = 0x1CC000
HDD_META_1 = 0x1C5000
HDD_META_2 = 0x1CE000

# EAP key area inside EMC_IPL_A
EAP_KEY_OFFSET = 0x024000
EAP_KEY_SIZE = 0x1000

# EAP HDD wrapped key blob (NVS area)
EAP_HDD_KEY_MAGIC = 0x1C91FC
EAP_HDD_KEY_BLOB = 0x1C9200
EAP_HDD_KEY_BACKUP_MAGIC = 0x1CC1FC
EAP_HDD_KEY_BACKUP_BLOB = 0x1CC200
EAP_HDD_KEY_BLOB_SIZE = 0x60  # default, _repair_eap_hdd_key uses detect_eap_key_size()

# Active slot indicator
ACT_SLOT_OFFSET = 0x1000


def _region_healthy(data, start, end, min_valued=64):
    """Region has more than min_valued non-0x00/non-0xFF bytes."""
    chunk = data[start:end]
    return sum(1 for b in chunk if b not in (0, 0xFF)) > min_valued


def _region_empty(data, start, end):
    chunk = data[start:end]
    return is_all_zeros(chunk) or is_all_ff(chunk)


def _read_serial(data, offset=SN_ABS_OFFSET):
    chunk = data[offset:offset+16]
    m = re.search(rb'\d{10,18}', chunk)
    if m:
        return m.group(0).decode('ascii')
    return None


def _fw_ver_str(data):
    """Decode FW_VER bytes at 0x1C906A -> 'XX.YY' or None."""
    b = data[FW_VER_ABS_OFFSET:FW_VER_ABS_OFFSET+2]
    if len(b) < 2 or b[0] == 0xFF or b[1] == 0xFF:
        return None
    return f'{b[1]:X}.{b[0]:02X}'


def _encode_fw_ver(fw_str):
    if not fw_str or fw_str == "Unknown":
        return b'\xFF\xFF'
    first = fw_str.split('<->')[0].split('\u2192')[0].strip()
    parts = first.split('.')
    try:
        major = int(parts[0], 16)
        minor = int(parts[1][:2], 16) if len(parts) > 1 else 0
        return bytes([minor, major])
    except:
        return b'\xFF\xFF'


def _partition_fw_from_md5(data):
    """Determine FW from EMC_IPL/EAP_KBL MD5."""
    for label, start, size, db in [
        ("EAP_KBL",   0x0C4000, 0x080000, EAP_KBL_MD5),
        ("EMC_IPL_A", 0x004000, 0x060000, EMC_IPL_MD5),
        ("EMC_IPL_B", 0x064000, 0x060000, EMC_IPL_MD5),
    ]:
        chunk = data[start:start+size]
        m5 = md5_hash(chunk).lower()
        if m5 in db:
            return db[m5]['fw'][0]
    return None


class AutoRepair:
    def __init__(self, data, donors_dir="donors", fws_dir="fws"):
        self.data = bytearray(data)
        self.donors_dir = donors_dir
        self.fws_dir = fws_dir
        self.donor_data = None
        self.donor_path = None
        self.report = []
        self.repair_count = 0
        self.skipped_count = 0

    def _log(self, msg, end="\n"):
        msg = self._colorize(msg)
        self.report.append(msg)

    def _colorize(self, msg: str) -> str:
        # Section headers
        if msg.startswith('=== '):
            return title(msg)
        if msg.startswith('--- '):
            return info(msg)
        # Status keywords
        msg = re.sub(r'(?<=: )(OK)$', lambda m: ok(m.group(1)), msg)
        msg = re.sub(r'(?<=: )(REPAIRED)\b', lambda m: ok(m.group(1)), msg)
        msg = re.sub(r'(?<=: )(SYNCED)\b', lambda m: ok(m.group(1)), msg)
        msg = re.sub(r'(?<=: )(ENABLED)\b', lambda m: ok(m.group(1)), msg)
        msg = re.sub(r'(?<=: )(FAILED)\b', lambda m: fail(m.group(1)), msg)
        # score=80.0
        msg = re.sub(r'(score=)([\d.]+)', lambda m: m.group(1) + value(m.group(2)), msg)
        # SKU=CUH-XXXX
        msg = re.sub(r'(SKU=)(\S+)', lambda m: m.group(1) + value(m.group(2)), msg)
        # FW=XX.XX
        msg = re.sub(r'(FW=)(\S+)', lambda m: m.group(1) + value(m.group(2)), msg)
        # Donor filename before (score=
        msg = re.sub(r'(Donor: )(\S+)', lambda m: m.group(1) + value(m.group(2)), msg)
        # Hex offsets
        msg = re.sub(r'(0x[0-9A-Fa-f]{4,8})', lambda m: value(m.group(1)), msg)
        return msg

    # ── Donor selection (v2 smart) ──────────────────────

    def _find_donor(self):
        target_sku = detect_sku(bytes(self.data))
        target_fw = detect_fw_version(bytes(self.data))
        if not os.path.isdir(self.donors_dir):
            self._log("  No donors/ directory found")
            return False

        # Use SmartDonorMatcher with caching disabled (scan fresh each repair)
        matcher = SmartDonorMatcher(self.donors_dir, use_cache=False)
        result = matcher.match(target_sku, target_fw)

        if result.best and result.best.score > 0:
            best = result.best
            self.donor_path = best.filepath
            try:
                with open(best.filepath, 'rb') as f:
                    self.donor_data = f.read()
                self._log(f"  Donor: {best.filename} (score={best.score} SKU={best.sku} FW={best.fw_version})")
                return True
            except Exception as e:
                self._log(f"  Error loading donor: {e}")

        # Fallback: original simple search
        self._log("  SmartMatcher found no match, falling back to direct scan...")
        best, best_score = None, -1
        for fname in sorted(os.listdir(self.donors_dir)):
            if not fname.upper().endswith('.BIN'):
                continue
            path = os.path.join(self.donors_dir, fname)
            try:
                d = open(path, 'rb').read()
            except Exception:
                continue
            if len(d) != 0x2000000:
                continue
            if _region_empty(d, 0x2000, 0x3000):
                continue
            sku = detect_sku(d)
            fw = detect_fw_version(d)
            score = 0
            if sku == target_sku:
                score += 60
            elif sku[:7] == target_sku[:7]:
                score += 30
            if fw == target_fw and fw != "Unknown":
                score += 40
            if score > best_score:
                best_score = score
                best = (path, d)
        if best:
            self.donor_path, self.donor_data = best
            self._log(f"  Donor (fallback): {os.path.basename(self.donor_path)} (score={best_score})")
            return True
        self._log("  No suitable donor found")
        return False

    def _donor_copy(self, start, end):
        if self.donor_data is None:
            return False
        if start >= len(self.donor_data) or end > len(self.donor_data):
            return False
        chunk = self.donor_data[start:end]
        if _region_empty(self.donor_data, start, end):
            return False
        self.data[start:end] = chunk
        return True

    # ── Phase 1: Boot Chain ──────────────────────────────

    def _repair_sce_header(self):
        if _region_healthy(self.data, 0x0000, 0x1000, min_valued=32):
            self._log("  SCE Header (0x0000-0x0FFF): OK")
            return True
        if self._donor_copy(0x0000, 0x2000):
            self._log("  SCE Header (0x0000-0x1FFF): REPAIRED from donor")
            self.repair_count += 1
            return True
        self._log("  SCE Header: FAILED (no donor)")
        return False

    def _repair_active_slot(self):
        """Active slot indicator at 0x1000 must be 0x00 (A) or 0x80 (B)."""
        b = self.data[ACT_SLOT_OFFSET]
        if b in (0x00, 0x80):
            slot = "A" if b == 0x00 else "B"
            self._log(f"  Active Slot (0x{ACT_SLOT_OFFSET:06X}): OK ({slot})")
            return True
        # Determine correct value from MBR1 flag
        mbr1 = _parse_mbr(self.data, MBR1_OFF)
        if mbr1 and mbr1.get("partitions"):
            for p in mbr1["partitions"]:
                if p["type"] in (0x20,) and p["flag"] == 0x01:
                    correct = 0x00  # A active
                    break
            else:
                correct = 0x80  # B active
        else:
            correct = 0x00
        self.data[ACT_SLOT_OFFSET] = correct
        self._log(f"  Active Slot: REPAIRED to 0x{correct:02X}")
        self.repair_count += 1
        return True

    def _repair_mbr(self):
        gen = MBRGenerator(bytes(self.data), self.donors_dir)
        if self.donor_data:
            gen.donor_info = (self.donor_path, self.donor_data)

        mbr1 = _parse_mbr(self.data, MBR1_OFF)
        mbr2 = _parse_mbr(self.data, MBR2_OFF)
        mbr1_ok = gen._mbr_valid(mbr1)
        mbr2_ok = gen._mbr_valid(mbr2)

        if mbr1_ok and mbr2_ok:
            self._log("  MBR1 (0x2000): OK")
            self._log("  MBR2 (0x3000): OK")
            return True

        for p, label, pos in [(mbr1, "MBR1", MBR1_OFF), (mbr2, "MBR2", MBR2_OFF)]:
            if p:
                flag_err = None
                emc = [x for x in p["partitions"] if x["type"] == 0x20]
                if len(emc) >= 2:
                    flags = [x["flag"] for x in emc]
                    if not (0x00 in flags and 0x01 in flags):
                        flag_err = "emc_ipl flags not opposite"
                if not flag_err and len(emc) < 2:
                    flag_err = "missing emc_ipl"
                types = set(x["type"] for x in p["partitions"])
                crit = {0x20, 0x21, 0x22, 0x26}
                missing = crit - types
                if flag_err or missing:
                    self._log(f"  {label} ({hex(pos)}): issues found")
                    if flag_err:
                        self._log(f"    - {flag_err}")
                    if missing:
                        self._log(f"    - missing types: {', '.join(hex(t) for t in missing)}")
            else:
                self._log(f"  {label} ({hex(pos)}): corrupt/unreadable")

        if gen.regenerate():
            self.data = bytearray(gen.get_data())
            for line in gen.get_report().split('\n'):
                self._log(f"  {line}")
            self.repair_count += 1
            return True
        self._log("  MBR repair: FAILED")
        return False

    # ── Phase 2: Firmware Partitions ─────────────────────

    def _repair_firmware_section(self, name, start, end):
        if _region_healthy(self.data, start, end):
            self._log(f"  {name} ({hex(start)}-{hex(end)}): OK")
            return True

        self._log(f"  {name}: DAMAGED - trying fws repair...")
        eng = RepairEngine(fws_dir=self.fws_dir)
        repaired, rep = eng.repair_from_fws(bytes(self.data), name)
        if any(r.get("status", "") == "REPAIRED_FROM_FWS" for r in rep):
            self.data = bytearray(repaired)
            self._log(f"  {name}: REPAIRED from fws")
            self.repair_count += 1
            return True

        if self._donor_copy(start, end):
            self._log(f"  {name}: REPAIRED from donor")
            self.repair_count += 1
            return True

        # Sibling copy for EMC_IPL
        if name == "EMC_IPL_A":
            sib_s, sib_e = 0x064000, 0x0C4000
        elif name == "EMC_IPL_B":
            sib_s, sib_e = 0x004000, 0x064000
        else:
            sib_s = sib_e = 0

        if sib_s and _region_healthy(self.data, sib_s, sib_e):
            sz = end - start
            self.data[start:end] = self.data[sib_s:sib_s+sz]
            self._log(f"  {name}: REPAIRED from sibling slot")
            self.repair_count += 1
            return True

        self._log(f"  {name}: FAILED (no source)")
        self.skipped_count += 1
        return False

    def _repair_eap_key(self):
        """EAP key area inside EMC_IPL_A at 0x24000."""
        s = EAP_KEY_OFFSET
        e = EAP_KEY_OFFSET + EAP_KEY_SIZE
        if _region_healthy(self.data, s, e):
            self._log(f"  EAP Key ({hex(s)}): OK")
            return True

        # Try sibling slot EAP key at +0x60000
        sib_s = s + 0x60000
        sib_e = e + 0x60000
        if _region_healthy(self.data, sib_s, sib_e):
            self.data[s:e] = self.data[sib_s:sib_e]
            self._log(f"  EAP Key: REPAIRED from sibling slot")
            self.repair_count += 1
            return True

        if self._donor_copy(s, e):
            self._log(f"  EAP Key: REPAIRED from donor")
            self.repair_count += 1
            return True

        # Last resort: generate random (better than brick)
        import os as _os
        rand = _os.urandom(EAP_KEY_SIZE)
        self.data[s:e] = rand
        self._log(f"  EAP Key: REGENERATED (random)")
        self.repair_count += 1
        return True

    # ── Phase 3: NVS sub-sections ────────────────────────

    def _repair_nvs_fw_ver(self):
        """Check NVS FW_VER matches actual partition FW. Fix if mismatch."""
        stored = _fw_ver_str(self.data)
        actual = _partition_fw_from_md5(self.data)
        if not actual:
            return  # can't verify

        if stored == actual:
            self._log(f"  NVS FW_VER: OK ({stored})")
            return

        self._log(f"  NVS FW_VER: MISMATCH stored={stored}, actual={actual} - fixing")
        self.data[FW_VER_ABS_OFFSET:FW_VER_ABS_OFFSET+2] = _encode_fw_ver(actual)
        self.report[-1] = f"  NVS FW_VER: REPAIRED ({stored} -> {actual})"
        self.repair_count += 1

    def _repair_nvs_serial(self):
        """Validate SN at 0x1C8030."""
        sn = _read_serial(self.data)
        if sn:
            self._log(f"  NVS SN (0x{SN_ABS_OFFSET:06X}): OK ({sn})")
            return True

        # Try from active slot string search
        for off in range(0x1C8020, 0x1C9000, 16):
            chunk = self.data[off:off+16]
            m = re.search(rb'\d{10,18}', chunk)
            if m:
                sn = m.group(0).decode('ascii')
                self.data[SN_ABS_OFFSET:SN_ABS_OFFSET+16] = sn.encode().ljust(16, b'\x00')
                self._log(f"  NVS SN: REPAIRED ({sn})")
                self.repair_count += 1
                return True

        if self._donor_copy(0x1C8000, 0x1C9000):
            self._log("  NVS SN: REPAIRED from donor")
            self.repair_count += 1
            return True

        self._log("  NVS SN: FAILED (no source)")
        return False

    def _repair_cid_mirrors(self):
        from .nvs_patcher import NVSPatcher
        nvsp = NVSPatcher(bytes(self.data))
        info = nvsp.analyze()
        cid_repairs = nvsp.repair_cid()
        unk_repairs = nvsp.repair_unk_blocks()

        # Sync half-corrupt mirrors only — never force-sync healthy-different pairs
        syncs = []
        for name, mirror in [("1CA", "1CD"), ("1C9", "1CC")]:
            i = info.get(name)
            im = info.get(mirror)
            if not i or not im:
                continue

            # Primary healthy, mirror empty/unhealthy — restore mirror
            if not i["empty"] and i["healthy"] and (im["empty"] or not im["healthy"]):
                r = nvsp.sync_cid(name, mirror)
                syncs.append(f"  CID {mirror}: RESTORED from {name}")
                self.repair_count += 1
            # Mirror healthy, primary empty/unhealthy — restore primary
            elif not im["empty"] and im["healthy"] and (i["empty"] or not i["healthy"]):
                r = nvsp.sync_cid(mirror, name)
                syncs.append(f"  CID {name}: RESTORED from {mirror}")
                self.repair_count += 1

        for r in syncs:
            self._log(r)

        all_repairs = cid_repairs + unk_repairs
        if all_repairs:
            for r in all_repairs:
                if "WARNING" not in r:
                    self._log(f"  {r}")
                    self.repair_count += 1
            self.data = bytearray(nvsp.get_data())
        if not all_repairs and not syncs:
            self._log("  CID 1CA/1CD: OK")
            self._log("  CID 1C9/1CC: OK")

    def _repair_hdd_metadata(self):
        """Sync HDD metadata at 0x1C5000 and 0x1CE000 + EAP key blob."""
        ok1 = _region_healthy(self.data, HDD_META_1, HDD_META_1+0x1000)
        ok2 = _region_healthy(self.data, HDD_META_2, HDD_META_2+0x1000)
        if ok1 and ok2:
            if self.data[HDD_META_1:HDD_META_1+0x1000] == self.data[HDD_META_2:HDD_META_2+0x1000]:
                self._log("  HDD Metadata (0x1C5000/0x1CE000): OK")
            else:
                self.data[HDD_META_2:HDD_META_2+0x1000] = self.data[HDD_META_1:HDD_META_1+0x1000]
                self._log("  HDD Metadata: SYNCED")
                self.repair_count += 1
            self._repair_eap_hdd_key()
            self._repair_hdd_info()
            return
        if ok1 and not ok2:
            self.data[HDD_META_2:HDD_META_2+0x1000] = self.data[HDD_META_1:HDD_META_1+0x1000]
            self._log("  HDD Metadata 0x1CE000: REPAIRED from 0x1C5000")
            self.repair_count += 1
        elif not ok1 and ok2:
            self.data[HDD_META_1:HDD_META_1+0x1000] = self.data[HDD_META_2:HDD_META_2+0x1000]
            self._log("  HDD Metadata 0x1C5000: REPAIRED from 0x1CE000")
            self.repair_count += 1
        else:
            if self._donor_copy(HDD_META_1, HDD_META_1+0x1000) and self._donor_copy(HDD_META_2, HDD_META_2+0x1000):
                self._log("  HDD Metadata: REPAIRED from donor")
                self.repair_count += 1
            else:
                self._log("  HDD Metadata: FAILED (no source)")
                self.skipped_count += 1
        self._repair_eap_hdd_key()
        self._repair_hdd_info()

    def _repair_hdd_info(self):
        """Restore HDD model/serial info at 0x1C9C00 from mirror or donor."""
        from ..v2_features.hdd_analyzer import _extract_hdd_info
        HDD_INFO_OFF = 0x1C9C00
        HDD_INFO_MIRROR = 0x1CCC00
        p = _extract_hdd_info(self.data, HDD_INFO_OFF)
        m = _extract_hdd_info(self.data, HDD_INFO_MIRROR)
        p_ok = p.get('clean', False) and p.get('has_data', False)
        m_ok = m.get('clean', False) and m.get('has_data', False)
        if p_ok and m_ok:
            if p['model'] == m['model'] and p['serial'] == m['serial']:
                self._log(f"  HDD Info ({hex(HDD_INFO_OFF)}): OK ({p['model']})")
            else:
                self.data[HDD_INFO_MIRROR:HDD_INFO_MIRROR+0x40] = self.data[HDD_INFO_OFF:HDD_INFO_OFF+0x40]
                self._log("  HDD Info mirror: SYNCED from primary")
                self.repair_count += 1
        elif not p_ok and m_ok:
            self.data[HDD_INFO_OFF:HDD_INFO_OFF+0x40] = self.data[HDD_INFO_MIRROR:HDD_INFO_MIRROR+0x40]
            self._log("  HDD Info: RESTORED from mirror")
            self.repair_count += 1
        elif p_ok and not m_ok:
            self.data[HDD_INFO_MIRROR:HDD_INFO_MIRROR+0x40] = self.data[HDD_INFO_OFF:HDD_INFO_OFF+0x40]
            self._log("  HDD Info mirror: RESTORED from primary")
            self.repair_count += 1
        else:
            restored = False
            # Try current donor
            if self.donor_data is not None:
                d = _extract_hdd_info(self.donor_data, HDD_INFO_OFF)
                if d.get('clean') and d.get('has_data'):
                    self.data[HDD_INFO_OFF:HDD_INFO_OFF+0x40] = self.donor_data[HDD_INFO_OFF:HDD_INFO_OFF+0x40]
                    self.data[HDD_INFO_MIRROR:HDD_INFO_MIRROR+0x40] = self.donor_data[HDD_INFO_MIRROR:HDD_INFO_MIRROR+0x40]
                    self._log(f"  HDD Info: REPAIRED from donor")
                    self.repair_count += 1
                    return
            # Scan all donors
            if os.path.isdir(self.donors_dir):
                for fname in sorted(os.listdir(self.donors_dir)):
                    if not fname.upper().endswith('.BIN'):
                        continue
                    try:
                        with open(os.path.join(self.donors_dir, fname), 'rb') as f:
                            d = f.read()
                        if len(d) >= HDD_INFO_MIRROR + 0x40:
                            di = _extract_hdd_info(d, HDD_INFO_OFF)
                            if di.get('clean') and di.get('has_data'):
                                self.data[HDD_INFO_OFF:HDD_INFO_OFF+0x40] = d[HDD_INFO_OFF:HDD_INFO_OFF+0x40]
                                self.data[HDD_INFO_MIRROR:HDD_INFO_MIRROR+0x40] = d[HDD_INFO_MIRROR:HDD_INFO_MIRROR+0x40]
                                self._log(f"  HDD Info: REPAIRED from {fname}")
                                self.repair_count += 1
                                return
                    except Exception:
                        continue
            self._log("  HDD Info: FAILED (corrupt, no clean donor)")
            self.skipped_count += 1

    def _repair_eap_hdd_key(self):
        """Restore EAP HDD wrapped key blob at 0x1C91FC/0x1C9200 from backup or donor."""
        from ..v2_features.hdd_analyzer import _is_valid_eap, detect_eap_key_size
        mg = EAP_HDD_KEY_MAGIC
        mb = EAP_HDD_KEY_BACKUP_MAGIC
        sz = detect_eap_key_size(bytes(self.data))
        p_valid = _is_valid_eap(self.data, mg, sz)
        b_valid = _is_valid_eap(self.data, mb, sz)
        if p_valid and b_valid:
            if self.data[mg:mg+4+sz] == self.data[mb:mb+4+sz]:
                self._log(f"  EAP HDD Key ({hex(mg+4)}): OK")
            else:
                self.data[mb:mb+4+sz] = self.data[mg:mg+4+sz]
                self._log("  EAP HDD Key backup: SYNCED from primary")
                self.repair_count += 1
        elif not p_valid and b_valid:
            self.data[mg:mg+4+sz] = self.data[mb:mb+4+sz]
            self._log("  EAP HDD Key: RESTORED from backup")
            self.repair_count += 1
        elif p_valid and not b_valid:
            self.data[mb:mb+4+sz] = self.data[mg:mg+4+sz]
            self._log("  EAP HDD Key backup: RESTORED from primary")
            self.repair_count += 1
        else:
            # Both corrupt — try current donor first
            if self.donor_data is not None:
                dsz = detect_eap_key_size(self.donor_data)
                if _is_valid_eap(self.donor_data, mg, dsz):
                    self.data[mg:mg+4+sz] = self.donor_data[mg:mg+4+dsz][:4+sz]
                    self.data[mb:mb+4+sz] = self.donor_data[mb:mb+4+dsz][:4+sz]
                    self._log("  EAP HDD Key: REPAIRED from donor")
                    self.repair_count += 1
                    return
            # Fallback: scan all donors for valid EAP key
            if os.path.isdir(self.donors_dir):
                for fname in sorted(os.listdir(self.donors_dir)):
                    if not fname.upper().endswith('.BIN'):
                        continue
                    if self.donor_path and os.path.basename(self.donor_path) == fname:
                        continue  # already tried
                    path = os.path.join(self.donors_dir, fname)
                    try:
                        with open(path, 'rb') as f:
                            d = f.read()
                        dsz = detect_eap_key_size(d)
                        if len(d) >= mb + 4 + dsz and _is_valid_eap(d, mg, dsz):
                            self.data[mg:mg+4+sz] = d[mg:mg+4+dsz][:4+sz]
                            self.data[mb:mb+4+sz] = d[mb:mb+4+dsz][:4+sz]
                            self._log(f"  EAP HDD Key: REPAIRED from {fname}")
                            self.repair_count += 1
                            return
                    except Exception:
                        continue
            self._log("  EAP HDD Key: FAILED (both copies corrupt, no valid donor)")
            self.skipped_count += 1

    def _repair_nvs_full(self):
        """Full NVS rebuild via NVSGenerator if critical corruption."""
        start, end = NVS_START, NVS_START+0xC000
        if _region_healthy(self.data, start, end):
            return False  # not needed, individual repairs above handle it
        self._log("  NVS: CRITICAL corruption - full rebuild...")

        # Try NVSGenerator first (legacy method)
        gen = NVSGenerator(bytes(self.data), self.donors_dir)
        if gen.find_best_donor():
            donor_path, donor_data, donor_sku, donor_fw = gen.donor_info
            # Try new NVS regeneration with Board ID-based method selection
            try:
                from ..v2_features.nvs_regen import (
                    extract_board_id, board_id_match_level,
                    nvs_regen_auto,
                )
                result, report = nvs_regen_auto(bytes(self.data), donor_data)
                for line in report:
                    self._log(line)
                self.data = bytearray(result)
                self.repair_count += 1
                return True
            except Exception:
                pass
            # Fallback to legacy NVSGenerator
            if gen.regenerate():
                self.data = bytearray(gen.get_data())
                for line in gen.get_report().split('\n'):
                    self._log(f"  {line}")
                self.repair_count += 1
                return True
        if self._donor_copy(start, end):
            self._log("  NVS: REPAIRED from donor (full)")
            self.repair_count += 1
            return True
        self._log("  NVS: FAILED (no source)")
        self.skipped_count += 1
        return False

    # ── Phase 4: UART / Debug Flags ─────────────────────

    def _repair_uart(self):
        """Enable UART if disabled at 0x1C931F."""
        if UART_OFFSET >= len(self.data):
            self._log(f"  UART (0x{UART_OFFSET:06X}): OFFSET OOB")
            return
        current = self.data[UART_OFFSET]
        if current == 0x01:
            self._log(f"  UART (0x{UART_OFFSET:06X}): OK (enabled)")
            return
        self.data[UART_OFFSET] = 0x01
        backup = UART_OFFSET + 0x3000
        if backup < len(self.data):
            self.data[backup] = 0x01
        self._log(f"  UART (0x{UART_OFFSET:06X}): ENABLED")
        self.repair_count += 1

    # ── Phase 5: CoreOS ──────────────────────────────────

    def _repair_coreos(self):
        slots = [
            ("CoreOS_A", 0x3C0000, 0x1080000),
            ("CoreOS_B", 0x1080000, 0x1D40000),
        ]
        healthy = None
        for name, s, e in slots:
            if _region_healthy(self.data, s, e):
                if healthy is None:
                    healthy = (name, s, e)
                self._log(f"  {name} ({hex(s)}-{hex(e)}): OK")
            else:
                sz = e - s
                if healthy:
                    self.data[s:e] = self.data[healthy[1]:healthy[1]+sz]
                    self._log(f"  {name}: REPAIRED from {healthy[0]}")
                    self.repair_count += 1
                elif self._donor_copy(s, e):
                    self._log(f"  {name}: REPAIRED from donor")
                    self.repair_count += 1
                else:
                    self._log(f"  {name}: FAILED (no source)")
                    self.skipped_count += 1

    # ── Main entry ───────────────────────────────────────

    def repair_all(self, fix_warnings=False):
        self.report = []
        self.repair_count = 0
        self.skipped_count = 0

        self._log("=== Auto-Repair Analysis ===")
        self._log("Finding best matching donor...")
        self._find_donor()

        self._log("")
        self._log("--- Phase 1: Boot Chain ---")
        self._repair_sce_header()
        self._repair_active_slot()
        self._repair_mbr()

        self._log("")
        self._log("--- Phase 2: Firmware Partitions ---")
        self._repair_firmware_section("EMC_IPL_A", 0x004000, 0x064000)
        self._repair_firmware_section("EMC_IPL_B", 0x064000, 0x0C4000)
        self._repair_eap_key()
        self._repair_firmware_section("EAP_KBL", 0x0C4000, 0x144000)
        self._repair_firmware_section("Torus", 0x144000, 0x1C4000)

        self._log("")
        self._log("--- Phase 3: NVS & CID ---")
        did_full_nvs = self._repair_nvs_full()
        if not did_full_nvs:
            self._repair_nvs_fw_ver()
            self._repair_nvs_serial()
        self._repair_hdd_metadata()
        self._repair_cid_mirrors()

        self._log("")
        self._log("--- Phase 4: UART / Debug ---")
        self._repair_uart()

        self._log("")
        self._log("--- Phase 5: CoreOS ---")
        self._repair_coreos()

        if fix_warnings:
            self._log("")
            self._log("--- Phase 6: Warnings Cleanup ---")
            self._log("Force NVS FW_VER sync with detected EMC_IPL range...")
            from ..utils.helpers import detect_fw_version, decode_nvs_fw
            current_fw = detect_fw_version(self.data)
            nvs_fw = decode_nvs_fw(self.data)
            if current_fw and nvs_fw and current_fw != nvs_fw:
                parts = current_fw.split('.')
                if len(parts) == 2:
                    try:
                        maj = int(parts[0])
                        minor_str = parts[1].split('<')[0].split('-')[0].strip()
                        minor = int(minor_str, 16)
                        self.data[FW_VER_ABS_OFFSET] = minor & 0xFF
                        self.data[FW_VER_ABS_OFFSET + 1] = maj & 0xFF
                        self._log(f"  NVS FW_VER updated: {nvs_fw} -> {current_fw}")
                        self.repair_count += 1
                    except ValueError:
                        self._log("  Could not parse detected FW version")
            self._log("Force CID mirrors sync...")
            self._repair_cid_mirrors()

        self._log("")
        total = self.repair_count + self.skipped_count
        if total == 0:
            self._log("No issues found - dump is healthy")
        else:
            self._log(f"Repairs applied: {self.repair_count}, Skipped: {self.skipped_count}")

        return self.repair_count > 0

    def get_data(self):
        return bytes(self.data)

    def get_report(self):
        return "\n".join(self.report)
