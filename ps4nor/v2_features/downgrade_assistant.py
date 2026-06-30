"""
Downgrade Assistant — NOR + Syscon analysis, slot switching, EAP_KBL replacement.
Wraps RevertAssistant with user-friendly flow.
"""

import os
from ..utils.helpers import detect_fw_version, detect_sku
from ..utils.fw_db import SWITCH_BLOBS, get_slot_switch_info
from ..utils.nor_defs import NVS_START
from ..patchers.revert_assistant import RevertAssistant


def _load_blob(fws_dir, section, fw_int, type_code):
    """Find best matching .2bls blob for a given FW and section."""
    sec_dir = os.path.join(fws_dir, section, f'{type_code:02X}')
    if not os.path.isdir(sec_dir):
        return None
    best = None
    best_range = None
    import re
    for fname in sorted(os.listdir(sec_dir)):
        if not fname.endswith('.2bls'):
            continue
        m = re.match(r'^(\d{4})-(\d{4})_([a-fA-F0-9]{32})\.2bls$', fname)
        if not m:
            continue
        bmin, bmax, _ = int(m.group(1)), int(m.group(2)), m.group(3).lower()
        if bmin <= fw_int <= bmax:
            if best is None or (bmax - bmin) < (best_range[1] - best_range[0]):
                best = fname
                best_range = (bmin, bmax)
    if best:
        path = os.path.join(sec_dir, best)
        with open(path, 'rb') as f:
            return f.read(), best
    return None


def _fw_str_to_int(fw_str):
    if not fw_str or fw_str == 'Unknown':
        return None
    parts = fw_str.split('.')
    try:
        return int(parts[0]) * 100 + int(parts[1][:2])
    except (ValueError, IndexError):
        return None


class DowngradeAssistant:
    def __init__(self, nor_data, syscon_data=None, fws_dir='fws', donors_dir='donors'):
        self.nor = bytearray(nor_data)
        self.syscon = bytearray(syscon_data) if syscon_data else None
        self.fws_dir = fws_dir
        self.donors_dir = donors_dir
        self.ra = RevertAssistant(nor_data, syscon_data or b'\xFF' * 0x40000)
        self.analysis = {}
        self.report = []

    def check_device_match(self):
        """Check if NOR and Syscon are from the same device.
        Returns dict with identity info and match status."""
        result = {
            'board_id': None,
            'board_id_hex': None,
            'mac': None,
            'mac_str': None,
            'serial': None,
            'nor_fw': None,
            'syscon_fw': 'Unknown',
            'syscon_matched': False,
            'matched': None,
            'arv_status': None,
            'arv_detail': '',
        }
        from ..utils.helpers import read_ascii_string
        nor = bytes(self.nor)
        if len(nor) > 0x1C4027:
            result['board_id'] = nor[0x1C4000:0x1C4008]
            result['board_id_hex'] = ':'.join('%02X' % b for b in result['board_id'])
            result['mac'] = nor[0x1C4021:0x1C4027]
            result['mac_str'] = ':'.join('%02X' % b for b in result['mac'])
            result['serial'] = read_ascii_string(nor, 0x1C8000, 64).strip()
        result['nor_fw'] = self.ra.analysis.get('fw_current_nvs')
        if self.syscon:
            from ..v2_features.syscon_fw_db import detect_syscon_fw, validate_syscon_pair
            sc_info = detect_syscon_fw(bytes(self.syscon))
            result['syscon_fw'] = sc_info.get('version', 'Unknown')
            result['syscon_matched'] = sc_info.get('matched', False)

            # ARV-based pairing validation
            pair_check = validate_syscon_pair(nor, bytes(self.syscon))
            result['arv_status'] = pair_check.get('status', 'unknown')
            result['arv_detail'] = pair_check.get('details', '')
            result['syscon_chip'] = pair_check.get('syscon_chip', sc_info.get('chip', 'Unknown'))
            result['syscon_arv'] = pair_check.get('syscon_arv', -1)
            result['expected_fw'] = pair_check.get('expected_fw', None)

            # Determine overall match
            if result['arv_status'] == 'matched':
                result['matched'] = True
            elif result['arv_status'] == 'mismatch':
                result['matched'] = False
            elif result['syscon_matched'] and result['nor_fw'] and result['nor_fw'] != 'Unknown':
                result['matched'] = (result['syscon_fw'] == result['nor_fw'])
        return result

    def analyze(self):
        nor_info = self.ra.analyze_nor()
        syscon_info = self.ra.analyze_syscon()
        self.analysis = {
            'nor': nor_info,
            'syscon': syscon_info,
        }

        # Determine FW per slot
        slot_fw = self.ra.slot_fw
        fw_a_min = slot_fw['slot_A']['min']
        fw_a_max = slot_fw['slot_A']['max']
        fw_b_min = slot_fw['slot_B']['min']
        fw_b_max = slot_fw['slot_B']['max']

        # Detect target: the lower FW slot
        target_slot = None
        target_fw = None
        if fw_a_min and fw_b_min:
            from ..utils.fw_db import fw_to_int
            a_low = fw_to_int(fw_a_min)
            a_high = fw_to_int(fw_a_max or fw_a_min)
            b_low = fw_to_int(fw_b_min)
            b_high = fw_to_int(fw_b_max or fw_b_min)
            if a_high < b_low:
                target_slot = 'A'
                target_fw = fw_a_max or fw_a_min
            elif b_high < a_low:
                target_slot = 'B'
                target_fw = fw_b_max or fw_b_min

        self.analysis['target_slot'] = target_slot
        self.analysis['target_fw'] = target_fw

        # Check CORE_SWCH patterns
        current_swch = self.ra.analysis.get('core_swch_name', 'Off')
        self.analysis['current_swch'] = current_swch

        return self.analysis

    def get_report(self):
        a = self.analysis.get('nor', {})
        s = self.analysis.get('syscon', {})
        lines = []

        lines.append('=== NOR Analysis ===')
        lines.append(f'  Active slot:       {a.get("act_slot", "?")}')
        lines.append(f'  CORE_SWCH:         {a.get("core_swch_name", "?")}')
        lines.append(f'  Current FW:        {a.get("fw_current", "?")}')
        lines.append(f'  NVS FW_VER:        {a.get("fw_current_nvs", "?")}')

        slot_fw = self.ra.slot_fw
        fwa = slot_fw.get('slot_A', {})
        fwb = slot_fw.get('slot_B', {})
        lines.append(f'  EMC_IPL A:         {fwa.get("min", "?")} - {fwa.get("max", "?")}')
        lines.append(f'  EMC_IPL B:         {fwb.get("min", "?")} - {fwb.get("max", "?")}')
        lines.append(f'  CoreOS A:          {"has data" if not a.get("coreos_a_empty", True) else "EMPTY"}')
        lines.append(f'  CoreOS B:          {"has data" if not a.get("coreos_b_empty", True) else "EMPTY"}')

        target_slot = self.analysis.get('target_slot')
        target_fw = self.analysis.get('target_fw')
        if target_slot:
            lines.append(f'  Target downgrade:  CoreOS_{target_slot} (FW {target_fw})')
        else:
            lines.append(f'  Target downgrade:  Cannot determine (same FW in both slots)')

        lines.append('')
        lines.append('=== Syscon SNVS Analysis ===')
        lines.append(f'  Entries:           {s.get("total_entries", "N/A")}')
        lines.append(f'  FW records:        {s.get("fw_record_count", "N/A")}')
        last = s.get('last_fw')
        if last:
            lines.append(f'  Last FW record:    FW_A ctr={last["fw_a"][2]} data={last["fw_a"][3].hex()}')

        return '\n'.join(lines)

    def _flip_core_swch(self):
        """Flip CORE_SWCH at 0x201000 to the opposite pattern."""
        current = list(self.nor[0x201000:0x201010])
        # Try to find the opposite pattern
        for i in range(0, len(SWITCH_BLOBS), 2):
            if i + 1 < len(SWITCH_BLOBS):
                if SWITCH_BLOBS[i]['v'] == current:
                    new_pat = SWITCH_BLOBS[i + 1]['v']
                    self.nor[0x201000:0x201010] = bytes(new_pat)
                    return True, f'Switched CORE_SWCH: [{i}] -> [{i+1}]'
                if SWITCH_BLOBS[i + 1]['v'] == current:
                    new_pat = SWITCH_BLOBS[i]['v']
                    self.nor[0x201000:0x201010] = bytes(new_pat)
                    return True, f'Switched CORE_SWCH: [{i+1}] -> [{i}]'
        # Unknown pattern: set to all 0xFF (common fallback)
        self.nor[0x201000:0x201010] = b'\xFF' * 16
        return True, 'CORE_SWCH: unknown pattern, set to 0xFF'

    def _replace_eap_kbl(self, target_fw_int, type_code):
        """Replace EAP_KBL with blob matching target FW."""
        blob_info = _load_blob(self.fws_dir, 'eap', target_fw_int, type_code)
        if blob_info:
            blob_data, blob_name = blob_info
            size = 0x80000
            trimmed = blob_data[:size] if len(blob_data) >= size else blob_data.ljust(size, b'\xFF')
            self.nor[0x0C4000:0x0C4000 + size] = trimmed
            return True, f'EAP_KBL replaced with {blob_name}'
        return False, f'No EAP_KBL blob for FW {target_fw_int} type {type_code:02X}'

    def _enable_uart(self):
        if 0x1C931F < len(self.nor):
            self.nor[0x1C931F] = 0x01
        bk = 0x1C931F + 0x3000
        if bk < len(self.nor):
            self.nor[bk] = 0x01

    def _enable_syscon_debug(self):
        if self.syscon and len(self.syscon) > 0x0C3:
            cur = self.syscon[0x0C3]
            if cur not in (0x84, 0x85):
                self.syscon[0x0C3] = 0x85
                return True
        return False

    def _patch_syscon(self, method='auto'):
        if not self.syscon or len(self.syscon) < 0x40000:
            return None, 'no syscon'
        from ..patchers.syscon_patcher import SysconSNVSPatcher
        sp = SysconSNVSPatcher(bytes(self.syscon))
        records = sp.find_fw_records()

        # Auto-detect method based on FW records vs NOR FW
        if method == 'auto':
            nor_fw = self.ra.analysis.get('fw_current_nvs')
            from ..v2_features.syscon_fw_db import detect_syscon_fw
            sc_info = detect_syscon_fw(bytes(self.syscon))
            sc_fw = sc_info.get('version', 'Unknown')
            sc_min = sc_info.get('min_nor_fw', '0.00')
            sc_max = sc_info.get('max_nor_fw', '99.99')

            if records and len(records) >= 2:
                if sc_fw != 'Unknown' and nor_fw and nor_fw != 'Unknown':
                    method = 'A' if sc_fw == nor_fw else 'B'
                else:
                    from ..utils.fw_db import fw_to_int
                    nf_int = fw_to_int(nor_fw) if nor_fw else 0
                    smin_int = fw_to_int(sc_min)
                    smax_int = fw_to_int(sc_max)
                    if smin_int <= nf_int <= smax_int:
                        method = 'A'
                    else:
                        method = 'B'
            else:
                method = 'A'

        if method == 'A':
            result = sp.remove_last_fw_record()
            return result, 'A' if result else None
        elif method == 'B':
            # Method B: remove entries from last FW record to end, keep flatdata
            if len(records) < 2:
                return sp.remove_last_fw_record(), 'A (fallback)'
            last = records[-1]
            fwa_pos = last['fw_a'][0]
            # Zero out the last 4 entries (FW record)
            for entry in [last['fw_a'], last['fw_b'], last['lic1'], last['lic2']]:
                pos = entry[0]
                if pos + 16 <= len(self.syscon):
                    self.syscon[pos:pos + 16] = b'\xFF' * 16
            return bytes(self.syscon), 'B'
        return None, 'no records'

    def downgrade(self, replace_eap=False, enable_uart=True, patch_syscon=True):
        """Execute downgrade. Returns (nor_result, syscon_result, report_lines)."""
        self.report = []
        applied = []

        # 1. Flip CORE_SWCH
        ok, msg = self._flip_core_swch()
        self.report.append(f'  {msg}')
        applied.append('CORE_SWCH')

        # 2. UART
        if enable_uart:
            self._enable_uart()
            self.report.append('  UART enabled')
            applied.append('UART')

        # 3. EAP_KBL replacement
        if replace_eap:
            a_info = self.ra.slot_fw.get('slot_A', {})
            target_slot = self.analysis.get('target_slot')
            target_slot_info = self.ra.slot_fw.get(f'slot_{target_slot}') if target_slot else None
            if not target_slot_info:
                target_slot = 'A'
                target_slot_info = self.ra.slot_fw.get('slot_A')
            if target_slot_info and target_slot_info.get('min'):
                tf = _fw_str_to_int(target_slot_info['min'])
                type_code = target_slot_info.get('type', 0)
                ok, msg = self._replace_eap_kbl(tf, type_code)
                self.report.append(f'  {msg}')
                if ok:
                    applied.append('EAP_KBL')

        # 4. Syscon DEBUG enable
        if patch_syscon and self.syscon:
            if self._enable_syscon_debug():
                self.report.append('  Syscon DEBUG enabled')
                applied.append('DEBUG')

        # 5. Syscon SNVS patch
        syscon_result = None
        syscon_method = None
        if patch_syscon:
            result, method = self._patch_syscon(method='auto')
            syscon_result = result
            syscon_method = method
            if result:
                self.report.append(f'  Syscon SNVS: Method {method} — last FW record removed')
                applied.append('Syscon')
            else:
                self.report.append(f'  Syscon SNVS: {method}')

        return bytes(self.nor), syscon_result, applied

    def get_data(self):
        return bytes(self.nor)
