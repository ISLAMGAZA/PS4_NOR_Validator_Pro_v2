import os
import time
from ..utils.nor_defs import (
    NOR_LAYOUT, COREOS_SLOTS, CID_REGIONS,
    SCE_MAGIC_STATIC_1, SCE_MAGIC_STATIC_2,
    STATUS_OK, STATUS_WARNING, STATUS_DANGER, STATUS_UNLISTED
)
from ..utils.helpers import (
    md5_hash, sha256_hash, entropy, is_all_zeros, is_all_ff,
    is_all_filled, read_ascii_string,
    detect_fw_version as _detect_fw_version, decode_nvs_fw,
    detect_sku, detect_mobo_serial, format_size, format_offset, load_md5_database
)
from ..utils.fw_db import EMC_IPL_MD5, EAP_KBL_MD5, TORUS_FW_MD5, is_fw_in_list


class ValidationResult:
    def __init__(self):
        self.filename = ""
        self.filepath = ""
        self.file_size = 0
        self.md5 = ""
        self.sha256 = ""
        self.sku = ""
        self.mobo_serial = ""
        self.fw_version = ""
        self.region = ""
        self.model_type = ""
        self.results = []
        self.ok_count = 0
        self.warning_count = 0
        self.danger_count = 0
        self.unlisted_count = 0
        self.elapsed = 0.0
        self.entropy_overall = 0.0
        self.validation_date = time.strftime("%Y-%m-%d %H:%M:%S")
        self.diagnosis = []
        self.suggestions = []
        self.partitions = {}
        self.nvs_fw = ""
        self.ipl_fw_range = ""

    def add_result(self, section, offset_start, offset_end, status, message, details=""):
        self.results.append({
            "section": section,
            "offset_start": offset_start,
            "offset_end": offset_end,
            "status": status,
            "message": message,
            "details": details,
        })
        if status == STATUS_OK:
            self.ok_count += 1
        elif status == STATUS_WARNING:
            self.warning_count += 1
        elif status == STATUS_DANGER:
            self.danger_count += 1
        elif status == STATUS_UNLISTED:
            self.unlisted_count += 1

    def add_diagnosis(self, issue, suggestion=""):
        self.diagnosis.append(issue)
        if suggestion:
            self.suggestions.append(suggestion)


class NORValidator:
    def __init__(self, data):
        self.data = data
        self.result = ValidationResult()
        self.md5_db = load_md5_database()

    def validate(self, filepath=""):
        t0 = time.time()
        if filepath:
            self.result.filepath = filepath
            self.result.filename = os.path.basename(filepath)

        self.result.file_size = len(self.data)
        self.result.md5 = md5_hash(self.data)
        self.result.sha256 = sha256_hash(self.data)
        self.result.sku = detect_sku(self.data)
        self.result.fw_version = _detect_fw_version(self.data)
        self.result.mobo_serial = detect_mobo_serial(self.data)
        self.result.entropy_overall = entropy(self.data)

        from ..utils.nor_defs import SKU_DATABASE, REGION_CODES
        raw_sku = self.result.sku
        if raw_sku and raw_sku != "Unknown":
            import re as _re
            sku_match = _re.match(r'CUH-(\d{4})', raw_sku)
            if sku_match:
                sku_key = f"CUH-{sku_match.group(1)}"
                if sku_key in SKU_DATABASE:
                    self.result.model_type = SKU_DATABASE[sku_key][0]
                    self.result.region = SKU_DATABASE[sku_key][1]
                else:
                    region_digit = sku_match.group(1)[-1]
                    self.result.region = REGION_CODES.get(region_digit, "Unknown")

        self._check_partitions_md5()
        self._check_file_size()
        self._check_sce_headers()
        self._check_active_slot()
        self._check_regions()
        self._check_coreos_slots()
        self._check_cid_regions()
        self._check_cid_consistency()
        self._check_filled_areas()
        self._check_emc_ipl()
        self._check_boot_integrity()
        self._check_uart()
        self._generate_diagnosis()

        t1 = time.time()
        self.result.elapsed = t1 - t0
        return self.result

    def _check_file_size(self):
        if len(self.data) == 0x2000000:
            self.result.add_result(
                "File Size", 0, len(self.data), STATUS_OK,
                f"Valid NOR dump ({format_size(len(self.data))})"
            )
        elif len(self.data) > 0x2000000:
            self.result.add_result(
                "File Size", 0, len(self.data), STATUS_WARNING,
                f"Larger than expected NOR ({format_size(len(self.data))}, expected 32.0 MB)"
            )
        else:
            self.result.add_result(
                "File Size", 0, len(self.data), STATUS_DANGER,
                f"Too small for NOR ({format_size(len(self.data))}, expected 32.0 MB)"
            )

    def _check_sce_headers(self):
        sce1 = self.data[0x0000:0x2000]
        if SCE_MAGIC_STATIC_1 in sce1:
            self.result.add_result(
                "SCE Header", 0x0000, 0x2000, STATUS_OK,
                "SCE Static Section 1: SONY COMPUTER ENTERTAINMENT INC."
            )
        elif SCE_MAGIC_STATIC_2 in sce1:
            self.result.add_result(
                "SCE Header", 0x0000, 0x2000, STATUS_WARNING,
                "SCE Static Section 1: Sony Computer Entertainment Inc. (alternate)"
            )
        else:
            self.result.add_result(
                "SCE Header", 0x0000, 0x2000, STATUS_DANGER,
                "SCE Header corrupted or missing"
            )

        sce2 = self.data[0x2000:0x3000]
        if SCE_MAGIC_STATIC_2 in sce2:
            self.result.add_result(
                "SCE_2 Header", 0x2000, 0x3000, STATUS_OK,
                "SCE_2 Static Section: Sony Computer Entertainment Inc."
            )
        else:
            self.result.add_result(
                "SCE_2 Header", 0x2000, 0x3000, STATUS_DANGER,
                "SCE_2 Header corrupted or missing"
            )

        sce3 = self.data[0x3000:0x4000]
        if SCE_MAGIC_STATIC_2 in sce3 or SCE_MAGIC_STATIC_1 in sce3:
            self.result.add_result(
                "SCE_3 Header", 0x3000, 0x4000, STATUS_OK,
                "SCE_3 Section present"
            )
        else:
            self.result.add_result(
                "SCE_3 Header", 0x3000, 0x4000, STATUS_DANGER,
                "SCE_3 Header corrupted or missing"
            )

    def _check_active_slot(self):
        slot0_byte = self.data[0x1000] if len(self.data) > 0x1000 else 0xFF
        slot1_byte = self.data[0x201000] if len(self.data) > 0x201000 else 0xFF

        def desc(byte):
            if byte == 0x00: return "A"
            if byte == 0x80: return "B"
            return "?"

        s0_active = desc(slot0_byte)
        s1_active = desc(slot1_byte)
        msg = f"Slot 0 active={s0_active} (0x{slot0_byte:02X}), Slot 1 active={s1_active} (0x{slot1_byte:02X})"

        status = STATUS_OK
        if slot0_byte not in (0x00, 0x80):
            status = STATUS_WARNING
            msg += " - Slot 0 byte invalid"
        if slot1_byte not in (0x00, 0x80):
            status = STATUS_WARNING
            msg += " - Slot 1 byte invalid"

        ip_la_ok = not is_all_zeros(self.data[0x004000:0x064000]) and not is_all_ff(self.data[0x004000:0x064000])
        ip_lb_ok = not is_all_zeros(self.data[0x064000:0x0C4000]) and not is_all_ff(self.data[0x064000:0x0C4000])

        active_ok = (s0_active == "A" and ip_la_ok) or (s0_active == "B" and ip_lb_ok) or s0_active == "?"
        if not active_ok:
            status = STATUS_DANGER
            msg += " - Active IPL slot is empty!"
        elif s0_active == "?" and not (ip_la_ok or ip_lb_ok):
            status = STATUS_DANGER
            msg += " - Both IPL slots empty"

        self.result.add_result("Active Slot", 0x1000, 0x2000, status, msg)

    def _check_regions(self):
        for name, start, end, desc in NOR_LAYOUT:
            if start >= len(self.data):
                break
            end = min(end, len(self.data))
            region_data = self.data[start:end]
            region_md5 = md5_hash(region_data)
            region_entropy = entropy(region_data)
            ff_pct = region_data.count(0xFF) / len(region_data) * 100
            zero_pct = region_data.count(0) / len(region_data) * 100

            status = STATUS_OK
            msg = f"{name}: {format_size(end-start)}, Entropy: {region_entropy:.2f}"

            is_filled = ff_pct > 99.5 or zero_pct > 99.5
            always_empty = {"Slot0 Spare", "Slot1 Spare", "EMC_IPL_A", "Active Slot", "S1 Active Slot"}
            if is_filled and name not in ("Header", "MBR1", "MBR2") and "CoreOS" not in name and name not in always_empty:
                status = STATUS_DANGER
                msg = f"{name}: EMPTY/FILLED ({format_size(end-start)})"
            elif region_entropy < 0.1 and not is_filled:
                status = STATUS_WARNING
                msg = f"{name}: Low entropy ({region_entropy:.2f}), possible corruption"
            elif region_entropy > 7.95:
                status = STATUS_WARNING
                msg = f"{name}: High entropy ({region_entropy:.2f}), possibly encrypted/random"

            if name in self.md5_db:
                known_md5 = self.md5_db[name]
                if region_md5 in known_md5:
                    status = STATUS_OK
                    msg = f"{name}: MD5 match (known good)"

            self.result.add_result(name, start, end, status, msg)

    def _check_coreos_slots(self):
        slot_data_list = []
        for i, (start, end) in enumerate(COREOS_SLOTS):
            if start >= len(self.data):
                break
            end = min(end, len(self.data))
            slot_data = self.data[start:end]
            slot_data_list.append(slot_data)
            slot_md5 = md5_hash(slot_data)
            slot_entropy = entropy(slot_data)
            ff_pct = slot_data.count(0xFF) / len(slot_data) * 100
            zero_pct = slot_data.count(0) / len(slot_data) * 100

            status = STATUS_OK
            msg = f"CoreOS Slot {i}: {format_size(end-start)}, Entropy: {slot_entropy:.2f}"

            is_filled = ff_pct > 99.5 or zero_pct > 99.5
            reserved_slot = (i in (0, 3))
            if is_filled:
                if reserved_slot:
                    status = STATUS_OK
                    msg = f"CoreOS Slot {i}: EMPTY (reserved slot, normal)"
                else:
                    status = STATUS_WARNING
                    msg = f"CoreOS Slot {i}: EMPTY"
            elif slot_entropy < 1.0 and not is_filled:
                status = STATUS_DANGER
                msg = f"CoreOS Slot {i}: Possibly corrupt (entropy: {slot_entropy:.2f})"
            elif slot_entropy < 4.0:
                status = STATUS_WARNING
                msg = f"CoreOS Slot {i}: Low entropy ({slot_entropy:.2f}), may be partially corrupt"

            self.result.add_result(f"CoreOS Slot {i}", start, end, status, msg)

        if len(slot_data_list) >= 2:
            for i in range(len(slot_data_list)):
                for j in range(i+1, len(slot_data_list)):
                    if slot_data_list[i] == slot_data_list[j]:
                        self.result.add_result(
                            "CoreOS Duplicate", COREOS_SLOTS[i][0], COREOS_SLOTS[j][1],
                            STATUS_WARNING,
                            f"Slot {i} and Slot {j} are identical (may indicate corruption)"
                        )

    def _check_cid_regions(self):
        for name, (start, end) in CID_REGIONS.items():
            if start >= len(self.data):
                continue
            end = min(end, len(self.data))
            region_data = self.data[start:end]
            ff_pct = region_data.count(0xFF) / len(region_data) * 100
            zero_pct = region_data.count(0) / len(region_data) * 100
            non_zero = sum(1 for b in region_data if b != 0)
            fill_ratio = 1.0 - (non_zero / len(region_data))

            status = STATUS_OK
            msg = f"{name}: OK"

            is_filled = ff_pct > 99.5 or zero_pct > 99.5
            if is_filled:
                status = STATUS_DANGER
                msg = f"{name}: EMPTY/FILLED - Console ID may be lost"
            elif fill_ratio > 0.8:
                sz = "FF" if ff_pct > zero_pct else "00"
                pct = max(ff_pct, zero_pct)
                status = STATUS_WARNING
                msg = f"{name}: Mostly {sz} ({pct:.0f}%) - possible partial corruption"

            self.result.add_result(f"CID {name}", start, end, status, msg)

    def _check_cid_consistency(self):
        pairs = [("1CA", "1CD"), ("1C9", "1CC")]
        for a, b in pairs:
            if a in CID_REGIONS and b in CID_REGIONS:
                s_a, e_a = CID_REGIONS[a]
                s_b, e_b = CID_REGIONS[b]
                data_a = self.data[s_a:min(e_a, len(self.data))]
                data_b = self.data[s_b:min(e_b, len(self.data))]
                min_len = min(len(data_a), len(data_b))
                if min_len == 0:
                    continue
                matching = sum(1 for i in range(min_len) if data_a[i] == data_b[i])
                match_pct = matching / min_len * 100
                if match_pct < 50:
                    self.result.add_diagnosis(
                        f"CID mismatch: {a} vs {b} only {match_pct:.0f}% match",
                        f"CID regions {a} and {b} should be similar; use NVS patcher to sync"
                    )
                    self.result.add_result(
                        "CID Consistency", s_a, e_b, STATUS_WARNING,
                        f"{a} vs {b}: {match_pct:.0f}% match (expected >90%)"
                    )

    def _check_filled_areas(self):
        for name, start, end, desc in NOR_LAYOUT:
            end = min(end, len(self.data))
            chunk = self.data[start:end]
            zeros = chunk.count(0)
            ff = chunk.count(0xFF)
            total = len(chunk)
            if total == 0:
                continue
            zero_pct = (zeros / total) * 100
            ff_pct = (ff / total) * 100
            if zero_pct > 95:
                if name not in ["Slot0 Spare", "Slot1 Spare", "EMC_IPL_A",
                                "Active Slot", "S1 Active Slot"]:
                    self.result.add_result(
                        f"Zero Check {name}", start, end, STATUS_WARNING,
                        f"{zero_pct:.1f}% zero bytes"
                    )

    def _check_partitions_md5(self):
        parts = {
            "EMC_IPL_A": (0x004000, 0x064000, EMC_IPL_MD5),
            "EMC_IPL_B": (0x064000, 0x0C4000, EMC_IPL_MD5),
            "EAP_KBL":   (0x0C4000, 0x144000, EAP_KBL_MD5),
            "Torus":     (0x144000, 0x1C4000, TORUS_FW_MD5),
        }
        self.result.nvs_fw = decode_nvs_fw(self.data) or ""
        for name, (start, end, db) in parts.items():
            chunk = self.data[start:end]
            if is_all_zeros(chunk) or is_all_ff(chunk):
                self.result.partitions[name] = {"md5": "", "fw_range": "EMPTY", "type_code": None}
                continue
            m = md5_hash(chunk).lower()
            info = db.get(m)
            if info:
                fw_list = info['fw']
                r = fw_list[0] if len(fw_list) == 1 else (fw_list[0] + ' - ' + fw_list[-1])
                self.result.partitions[name] = {"md5": m, "fw_range": r, "type_code": info.get('t', 0)}
                nvs = self.result.nvs_fw
                if nvs and not is_fw_in_list(nvs, fw_list):
                    self.result.add_result(
                        f"{name}_FW", start, end, STATUS_WARNING,
                        f"FW {nvs} outside partition range ({r})"
                    )
            else:
                self.result.partitions[name] = {"md5": m, "fw_range": "UNKNOWN", "type_code": None}

    def _check_emc_ipl(self):
        emc_ipl_a = self.data[0x004000:0x064000]
        emc_ipl_b = self.data[0x064000:0x0C4000]
        a_empty = is_all_zeros(emc_ipl_a) or is_all_ff(emc_ipl_a)
        b_empty = is_all_zeros(emc_ipl_b) or is_all_ff(emc_ipl_b)

        if a_empty:
            self.result.add_result(
                "EMC_IPL_A", 0x004000, 0x064000, STATUS_OK,
                "EMC IPL A empty (backup slot, normal)"
            )
        if b_empty:
            self.result.add_result(
                "EMC_IPL_B", 0x064000, 0x0C4000, STATUS_WARNING,
                "EMC IPL B empty - boot will fail without IPL"
            )
            self.result.add_diagnosis(
                "EMC IPL B is empty - no active IPL",
                "Repair from fws/emc blob with matching FW version range"
            )

    def _check_boot_integrity(self):
        boot_chain = {
            "Header":     (0x000000, 0x001000),
            "MBR1":       (0x002000, 0x003000),
            "MBR2":       (0x003000, 0x004000),
            "EMC_IPL_B":  (0x064000, 0x0C4000),
            "EAP_KBL":    (0x0C4000, 0x144000),
            "Torus":      (0x144000, 0x1C4000),
        }
        boot_empty = []
        for name, (start, end) in boot_chain.items():
            chunk = self.data[start:min(end, len(self.data))]
            if is_all_zeros(chunk) or is_all_ff(chunk):
                boot_empty.append(name)
        if boot_empty:
            critical = [b for b in boot_empty if b != "EMC_IPL_A"]
            if critical:
                self.result.add_result(
                    "Boot Chain", 0x000000, 0x1C4000, STATUS_DANGER,
                    f"Boot chain broken: {', '.join(critical)} missing"
                )

    def _check_uart(self):
        from ..utils.nor_defs import UART_OFFSET
        off = UART_OFFSET
        if off < len(self.data):
            val = self.data[off]
            if val == 0x01:
                self.result.add_result(
                    "UART", off, off+1, STATUS_OK,
                    f"UART enabled at 0x{off:06X} (byte=0x01)"
                )
            elif val == 0x00:
                self.result.add_result(
                    "UART", off, off+1, STATUS_OK,
                    f"UART disabled at 0x{off:06X}"
                )
            else:
                self.result.add_result(
                    "UART", off, off+1, STATUS_WARNING,
                    f"UART byte at 0x{off:06X} = 0x{val:02X} (expected 0x00/0x01)"
                )

    def _generate_diagnosis(self):
        if not self.result.diagnosis:
            self.result.add_diagnosis(
                "No critical issues detected",
                "NOR dump appears healthy"
            )
