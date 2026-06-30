import os, hashlib
from ..utils.helpers import detect_sku, detect_fw_version
from ..utils.fw_db import TORUS_FW_MD5, SOUTHBRIDGES, detect_southbridge
from ..utils.nor_defs import TORUS_OFF, TORUS_SIZE, MAC_OFF, WIFI_5G_OFF


TORUS_VERS = [
    {'code': 0x03, 'name': 'Marvell 88W8797 V1',       'ic': ['J20H071', 'SP88W8797']},
    {'code': 0x22, 'name': 'Marvell 88W8897 V2',       'ic': ['AW-CB262', 'AW-NB218', 'DHSM-PS97', 'J20H091']},
    {'code': 0x30, 'name': 'MediaTek MT7667BSN V3',    'ic': ['AW-CB319', 'J20H096']},
]


class TorusPatcher:
    def __init__(self, data, fws_dir='fws'):
        self.data = bytearray(data)
        self.fws_dir = fws_dir

    def get_info(self):
        torus_data = bytes(self.data[TORUS_OFF:TORUS_OFF + TORUS_SIZE])
        md5 = hashlib.md5(torus_data).hexdigest()
        mac = bytes(self.data[MAC_OFF:MAC_OFF+6])
        s5g = self.data[WIFI_5G_OFF]

        info = TORUS_FW_MD5.get(md5)
        torus_code = info['t'] if info else 0
        fw_range = info['fw'] if info else []

        tv = '?'
        for v in TORUS_VERS:
            if v['code'] == torus_code:
                tv = v['name']
                break

        return {
            'md5': md5,
            'code': torus_code,
            'version': tv,
            'fw': fw_range,
            'mac': ':'.join(f'{b:02X}' for b in mac),
            '5g': 'Yes' if s5g == 0x01 else 'No',
            'healthy': info is not None,
        }

    def _find_matching_fws(self):
        torus_data = bytes(self.data[TORUS_OFF:TORUS_OFF + TORUS_SIZE])
        md5 = hashlib.md5(torus_data).hexdigest()
        info = TORUS_FW_MD5.get(md5)
        if not info:
            return []

        code = info['t']
        torus_dir = os.path.join(self.fws_dir, 'torus', f'{code:02X}')
        if not os.path.isdir(torus_dir):
            return []

        results = []
        for fname in sorted(os.listdir(torus_dir)):
            if fname.upper().endswith('.2BLS') or fname.upper().endswith('.BIN') or fname.upper().endswith('.SLB2'):
                path = os.path.join(torus_dir, fname)
                try:
                    with open(path, 'rb') as f:
                        fdata = f.read()
                    fmd5 = hashlib.md5(fdata).hexdigest()
                    results.append({'path': path, 'md5': fmd5, 'name': fname})
                except Exception:
                    pass
        return results

    def repair(self, fws_path=None):
        if fws_path:
            with open(fws_path, 'rb') as f:
                donor_data = f.read()
            self.data[TORUS_OFF:TORUS_OFF + TORUS_SIZE] = donor_data[:TORUS_SIZE]
            return f"Torus replaced from {os.path.basename(fws_path)}"

        matches = self._find_matching_fws()
        if not matches:
            return "No matching Torus firmware found in fws/torus/"

        torus_data = bytes(self.data[TORUS_OFF:TORUS_OFF + TORUS_SIZE])
        current_md5 = hashlib.md5(torus_data).hexdigest()

        for m in matches:
            if m['md5'] != current_md5:
                with open(m['path'], 'rb') as f:
                    donor_data = f.read()
                self.data[TORUS_OFF:TORUS_OFF + TORUS_SIZE] = donor_data[:TORUS_SIZE]
                return f"Torus replaced with {m['name']}"

        return "Torus already matches best available firmware"

    def get_data(self):
        return bytes(self.data)
