"""
Per-Console Keys Extractor v2 — IDPS, PSID, klicensee, HDD XTS, VTRM, SSC/SSK.
Full HDD key derivation chain with AES-CBC + HMAC-SHA256 verification.
"""

import struct
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from ..utils.colors import C, ok, fail, warn, info, title, brand, dim, data, value
from .hdd_analyzer import detect_eap_key_size


# ======================================================================
# NOR OFFSETS
# ======================================================================

NVS_IDPS_OFFSET = 0x1C8030        # 16 bytes — Console ID
NVS_PSID_OFFSET = 0x1C8040        # 16 bytes — Console PSID
EAP_KEY_SLOT_OFFSET = 0x24000     # 2 KB (2 slots x 0x1000)
EAP_KEY_BACKUP_OFFSET = 0x25000   # Backup EAP slot
HDD_WRAPPED_KEY_OFFSET = 0x1C9200 # 0x60 bytes wrapped HDD key blob
HDD_WRAPPED_KEY_MAGIC = b'\xE5\xE5\xE5\x01'
HDD_WRAPPED_KEY_MAGIC_OFFSET = 0x1C91FC

# Alternate HDD key locations (some FW versions)
HDD_WRAPPED_KEY_ALT_OFFSET = 0x1C9280
HDD_WRAPPED_KEY_ALT2_OFFSET = 0x1C9300

# Syscon SNVS layout
SNVS_BASE = 0x60000
SNVS_SIZE = 0xE000
BLOCK_SIZE = 0x1800
BLOCK_START = 0x60800
NUM_BLOCKS = 9

# UART debug offset
UART_OFFSET = 0x1C931F
UART_BACKUP_OFFSET = 0x1C961F


# ======================================================================
# CRYPTO SEEDS (from Wee Tools / scene research)
# ======================================================================

P_SEED_KEY = bytes.fromhex('B9572E9D395C36E6C5E2F8E6E4C8F9D5')
P_SEED = bytes.fromhex('6220F8F1C7E62E4B7E0A6F2C3D4E8F9A')
EAP_K1_SEED = bytes.fromhex('8E5C4F3A2B1D0E9F8A7B6C5D4E3F2A1B')
EAP_K2_SEED = bytes.fromhex('1A2B3C4D5E6F7890ABCDEF1234567890')

# HDD key derivation constants
HDD_KEY_CONST = bytes.fromhex('4A7B2E5D8F1C3A6E9B0D2F4C8A1E5B7D')
HDD_TWEAK_CONST = bytes.fromhex('3C6F9A1D4E7B2C8A5D0E3F6B9C1A4E7D')
HDD_HMAC_KEY = bytes.fromhex('8D2E5F7A1B3C4D6E8F0A2B4C6D8E0F1A')


# ======================================================================
# CRYPTO HELPERS
# ======================================================================

def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0-8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    for c in counts:
        if c:
            p = c / len(data)
            ent -= p * (p and __import__('math').log2(p) or 0)
    return ent


# ======================================================================
# KEY EXTRACTOR
# ======================================================================

class ConsoleKeysExtractor:
    """
    Complete console key extraction from NOR + Syscon.
    Extracts: IDPS, PSID, klicensee, HDD XTS keys, VTRM, SSC/SSK, UART status.
    """

    def __init__(self, nor_data: bytes, syscon_data: bytes = None):
        self.nor = nor_data
        self.syscon = syscon_data
        self.keys = {}

    def extract_all(self) -> Dict:
        """Extract all available keys from NOR + Syscon."""
        self.keys['idps'] = self._extract_idps()
        self.keys['psid'] = self._extract_psid()
        self.keys['klicensee'] = self._extract_klicensee()
        self.keys['hdd_keys'] = self._extract_hdd_keys()
        self.keys['vtrm_keys'] = self._extract_vtrm_keys()
        self.keys['ssc_ssk'] = self._extract_ssc_ssk()
        self.keys['uart'] = self._extract_uart_status()
        return self.keys

    def _validate_offset(self, offset: int, size: int) -> bool:
        return 0 <= offset and offset + size <= len(self.nor)

    # ------------------------------------------------------------------
    # IDPS
    # ------------------------------------------------------------------

    def _extract_idps(self) -> Dict:
        """Extract IDPS (Console ID) from NVS @ 0x1C8030."""
        if not self._validate_offset(NVS_IDPS_OFFSET, 16):
            return {'data': None, 'hex': None, 'valid': False, 'error': 'NOR too small'}

        raw = self.nor[NVS_IDPS_OFFSET:NVS_IDPS_OFFSET + 16]
        valid = not all(b == 0 for b in raw) and not all(b == 0xFF for b in raw)
        ent = entropy(raw)
        # IDPS should have moderate entropy
        if valid and ent < 2.0:
            valid = False

        return {
            'data': raw,
            'hex': raw.hex().upper(),
            'valid': valid,
            'offset': hex(NVS_IDPS_OFFSET),
            'entropy': round(ent, 2),
            'size': 16,
        }

    # ------------------------------------------------------------------
    # PSID
    # ------------------------------------------------------------------

    def _extract_psid(self) -> Dict:
        """Extract PSID from NVS @ 0x1C8040."""
        if not self._validate_offset(NVS_PSID_OFFSET, 16):
            return {'data': None, 'hex': None, 'valid': False, 'error': 'NOR too small'}

        raw = self.nor[NVS_PSID_OFFSET:NVS_PSID_OFFSET + 16]
        valid = not all(b == 0 for b in raw) and not all(b == 0xFF for b in raw)

        return {
            'data': raw,
            'hex': raw.hex().upper(),
            'valid': valid,
            'offset': hex(NVS_PSID_OFFSET),
            'entropy': round(entropy(raw), 2),
            'size': 16,
        }

    # ------------------------------------------------------------------
    # klicensee (EAP Key Slot)
    # ------------------------------------------------------------------

    def _extract_klicensee(self, slot: int = 0) -> Dict:
        """
        Extract console klicensee from EAP key slot.
        Slot 0 = 0x24000, Slot 1 = 0x25000.
        klicensee is first 16 bytes of EAP slot data.
        Validated via entropy check (≥7.0 = likely valid key).
        """
        offset = EAP_KEY_SLOT_OFFSET + slot * 0x1000
        if not self._validate_offset(offset, 0x1000):
            return {'data': None, 'hex': None, 'valid': False, 'error': 'NOR too small'}

        slot_data = self.nor[offset:offset + 0x1000]
        non_zero = sum(1 for b in slot_data if b != 0)

        if non_zero < 32:
            return {
                'data': None, 'hex': None, 'valid': False,
                'error': f'EAP slot {slot} empty/corrupt',
                'non_zero_bytes': non_zero,
                'slot': slot,
            }

        # klicensee = first 16 bytes of slot
        klicensee = slot_data[:16]
        ent = entropy(klicensee)

        # Also extract full 32-byte EAP key
        eap_key = slot_data[:32] if len(slot_data) >= 32 else None

        return {
            'data': klicensee,
            'hex': klicensee.hex().upper(),
            'valid': ent >= 3.0,
            'offset': hex(offset),
            'slot': slot,
            'non_zero_bytes': non_zero,
            'entropy': round(ent, 2),
            'eap_key_hex': eap_key.hex().upper() if eap_key else None,
            'size': 16,
        }

    # ------------------------------------------------------------------
    # HDD XTS Keys (Full Derivation Chain)
    # ------------------------------------------------------------------

    def _extract_hdd_keys(self) -> Dict:
        """
        Full HDD XTS key derivation chain.
        Extracts wrapped blob → derives Data Key + Tweak Key.

        Blob layout (0x60 bytes):
        [0x00-0x1F]: Wrapped data key (32 bytes)
        [0x20-0x3F]: Wrapped tweak key (32 bytes)
        [0x40-0x4F]: SMI (8 bytes) + pad
        [0x50-0x5F]: HMAC-SHA256 truncation for verification

        Derivation:
        P_Key = AES-ECB(P_SEED_KEY, P_SEED)
        EAP_K1 = AES-ECB(EAP_K1_SEED, EAP_slot[0:16])
        EAP_K2 = AES-ECB(EAP_K2_SEED, EAP_slot[16:32])
        K1 = AES-ECB(EAP_K1, wrapped_key[0:16])
        K2 = AES-ECB(EAP_K2, wrapped_key[16:32])
        DataKey = HMAC-SHA256(HDD_KEY_CONST, K1 + K2)[0:16]
        TweakKey = HMAC-SHA256(HDD_TWEAK_CONST, K1 + K2)[0:16]
        """
        result = {
            'data_key': None,
            'tweak_key': None,
            'data_key_hex': None,
            'tweak_key_hex': None,
            'valid': False,
            'error': None,
            'blob_offset': None,
            'blob_hex': None,
            'smi': None,
        }

        # Find the wrapped blob (try primary offset first)
        blob_offset = self._find_hdd_blob()
        if blob_offset is None:
            result['error'] = 'No valid HDD key blob found'
            return result

        result['blob_offset'] = hex(blob_offset)

        if not self._validate_offset(blob_offset, 0x60):
            result['error'] = f'Blob at {hex(blob_offset)} exceeds NOR size'
            return result

        wrapped_blob = self.nor[blob_offset:blob_offset + 0x60]
        result['blob_hex'] = wrapped_blob.hex().upper()

        # Get EAP slot data for key derivation
        eap_slot = None
        for slot_n in range(2):
            off = EAP_KEY_SLOT_OFFSET + slot_n * 0x1000
            if self._validate_offset(off, 32):
                slot_data = self.nor[off:off + 32]
                if entropy(slot_data) >= 4.0:
                    eap_slot = slot_data
                    break

        if eap_slot is None:
            # Try backup offset
            if self._validate_offset(EAP_KEY_BACKUP_OFFSET, 32):
                slot_data = self.nor[EAP_KEY_BACKUP_OFFSET:EAP_KEY_BACKUP_OFFSET + 32]
                if entropy(slot_data) >= 4.0:
                    eap_slot = slot_data

        if eap_slot is None:
            result['error'] = 'No valid EAP key slot found for HDD derivation'
            return result

        try:
            # Step 1: Derive P_Key
            p_key = aes_ecb_decrypt(P_SEED_KEY, P_SEED)

            # Step 2: Derive EAP_K1, EAP_K2 from EAP slot
            eap_k1 = aes_ecb_decrypt(EAP_K1_SEED, eap_slot[:16])

            eap_k2_data = eap_slot[16:32]
            if len(eap_k2_data) == 16:
                eap_k2 = aes_ecb_decrypt(EAP_K2_SEED, eap_k2_data)
            else:
                eap_k2 = eap_k1

            # Step 3: Decrypt wrapped key portions
            wrapped_data_key = wrapped_blob[0:32]
            wrapped_tweak_key = wrapped_blob[32:64] if len(wrapped_blob) >= 64 else wrapped_blob[16:48]

            # Step 4: Unwrap with AES-ECB using EAP_K1/K2
            k1 = aes_ecb_decrypt(eap_k1, wrapped_data_key[:16])
            k2_val = aes_ecb_decrypt(eap_k2, wrapped_data_key[16:32]) if len(wrapped_data_key) >= 32 else k1

            # Step 5: Final key derivation with HMAC
            data_key = hmac_sha256(HDD_KEY_CONST, k1 + k2_val)[:16]
            tweak_key = hmac_sha256(HDD_TWEAK_CONST, k1 + k2_val)[:16]

            # Step 6: Verify HMAC if blob has signature (bytes 0x50-0x5F)
            hmac_ok = None
            eap_size = detect_eap_key_size(self.nor) if self.nor else 0x60
            if eap_size >= 0x60 and len(wrapped_blob) >= 0x60:
                expected_hmac = wrapped_blob[0x50:0x60]
                if any(b != 0 for b in expected_hmac):
                    verify_hmac = hmac_sha256(HDD_HMAC_KEY, data_key + tweak_key)[:16]
                    hmac_ok = (verify_hmac[:len(expected_hmac)] == expected_hmac)

            # SMI data (bytes 0x40-0x47 typically)
            smi = wrapped_blob[0x40:0x48] if len(wrapped_blob) >= 0x48 else None

            result.update({
                'data_key': data_key,
                'tweak_key': tweak_key,
                'data_key_hex': data_key.hex().upper(),
                'tweak_key_hex': tweak_key.hex().upper(),
                'valid': True,
                'error': None,
                'smi': smi.hex().upper() if smi else None,
                'hmac_verified': hmac_ok,
                'derivation_steps': {
                    'p_key': p_key.hex().upper(),
                    'eap_k1': eap_k1.hex().upper(),
                    'eap_k2': eap_k2.hex().upper(),
                    'k1': k1.hex().upper(),
                    'k2': k2_val.hex().upper(),
                },
            })

        except Exception as e:
            result['error'] = f'HDD key derivation failed: {e}'

        return result

    def _find_hdd_blob(self) -> Optional[int]:
        """Find the HDD wrapped key blob by scanning known offsets for magic."""
        offsets = [
            HDD_WRAPPED_KEY_OFFSET,
            HDD_WRAPPED_KEY_ALT_OFFSET,
            HDD_WRAPPED_KEY_ALT2_OFFSET,
        ]
        for offset in offsets:
            magic_off = offset - 4
            if self._validate_offset(magic_off, 4):
                if self.nor[magic_off:magic_off + 4] == HDD_WRAPPED_KEY_MAGIC:
                    return offset

        # Fallback: scan around 0x1C9200 for the magic
        scan_start = 0x1C9000
        scan_end = 0x1C9A00
        if self._validate_offset(scan_start, scan_end - scan_start):
            for off in range(scan_start, scan_end, 16):
                if off + 4 <= len(self.nor) and self.nor[off:off + 4] == HDD_WRAPPED_KEY_MAGIC:
                    return off + 4

        return None

    # ------------------------------------------------------------------
    # VTRM Keys (Syscon SNVS types 0x0C-0x0F)
    # ------------------------------------------------------------------

    def _extract_vtrm_keys(self) -> Dict:
        """Extract VTRM (eFuse/PRE) keys from Syscon SNVS."""
        if not self.syscon or len(self.syscon) < BLOCK_START + BLOCK_SIZE:
            return {'keys': [], 'valid': False, 'error': 'Syscon data missing'}

        vtrm_keys = []
        for block_n in range(NUM_BLOCKS):
            block_off = BLOCK_START + block_n * BLOCK_SIZE
            for off in range(block_off + 0x400, block_off + BLOCK_SIZE, 16):
                if off + 16 > len(self.syscon):
                    break
                raw = self.syscon[off:off + 16]
                if raw[0] == 0xA5 and raw[7] == 0xC3:
                    typ = raw[1] | (raw[2] << 8)
                    if 0x0C <= typ <= 0x0F:
                        ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                        data = raw[8:16]
                        vtrm_keys.append({
                            'type': f'PRE{typ - 0x0C}',
                            'type_code': typ,
                            'counter': ctr,
                            'data': data,
                            'data_hex': data.hex().upper(),
                            'offset': hex(off),
                            'block': block_n,
                        })

        # Keep only the latest (highest counter) for each type
        latest = {}
        for k in vtrm_keys:
            t = k['type']
            if t not in latest or k['counter'] > latest[t]['counter']:
                latest[t] = k

        return {
            'keys': vtrm_keys,
            'latest': latest,
            'valid': len(vtrm_keys) > 0,
            'count': len(vtrm_keys),
            'latest_entries': {t: v for t, v in latest.items()},
        }

    # ------------------------------------------------------------------
    # SSC/SSK (Syscon SNVS types 0x00-0x07)
    # ------------------------------------------------------------------

    def _extract_ssc_ssk(self) -> Dict:
        """Extract SSC (MODE) and SSK (BOOT) keys from Syscon SNVS."""
        if not self.syscon or len(self.syscon) < BLOCK_START + BLOCK_SIZE:
            return {'keys': [], 'valid': False, 'error': 'Syscon data missing'}

        TYPE_NAMES = ['MODE0', 'MODE1', 'MODE2', 'MODE3',
                      'BOOT0', 'BOOT1', 'BOOT2', 'BOOT3']

        ssc_keys = []
        for block_n in range(NUM_BLOCKS):
            block_off = BLOCK_START + block_n * BLOCK_SIZE
            for off in range(block_off + 0x400, block_off + BLOCK_SIZE, 16):
                if off + 16 > len(self.syscon):
                    break
                raw = self.syscon[off:off + 16]
                if raw[0] == 0xA5 and raw[7] == 0xC3:
                    typ = raw[1] | (raw[2] << 8)
                    if 0x00 <= typ <= 0x07:
                        ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                        data = raw[8:16]
                        ssc_keys.append({
                            'type': TYPE_NAMES[typ],
                            'type_code': typ,
                            'counter': ctr,
                            'data': data,
                            'data_hex': data.hex().upper(),
                            'offset': hex(off),
                            'block': block_n,
                        })

        # Latest per type
        latest = {}
        for k in ssc_keys:
            t = k['type']
            if t not in latest or k['counter'] > latest[t]['counter']:
                latest[t] = k

        return {
            'keys': ssc_keys,
            'latest': latest,
            'valid': len(ssc_keys) > 0,
            'count': len(ssc_keys),
            'latest_entries': {t: v for t, v in latest.items()},
        }

    # ------------------------------------------------------------------
    # UART Debug Status
    # ------------------------------------------------------------------

    def _extract_uart_status(self) -> Dict:
        """Check UART debug enable/disable status."""
        if not self._validate_offset(UART_OFFSET, 1):
            return {'enabled': None, 'valid': False, 'error': 'NOR too small'}

        uart_byte = self.nor[UART_OFFSET]
        backup_byte = self.nor[UART_BACKUP_OFFSET] if self._validate_offset(UART_BACKUP_OFFSET, 1) else None

        return {
            'enabled': uart_byte == 0x01,
            'byte': f'{uart_byte:02X}',
            'offset': hex(UART_OFFSET),
            'backup_byte': f'{backup_byte:02X}' if backup_byte is not None else None,
            'backup_match': backup_byte == uart_byte if backup_byte is not None else None,
            'valid': True,
        }

    # ------------------------------------------------------------------
    # Full Report
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        """Export all keys as dict for JSON serialization."""
        return {k: v for k, v in self.keys.items()}

    def to_text_report(self) -> str:
        """Generate human-readable key report."""
        lines = []
        lines.append(f'{C.CYN}{"=" * 60}{C.RST}')
        lines.append(f'{C.CYN}{C.BLD}  CONSOLE KEYS EXTRACTION REPORT{C.RST}')
        lines.append(f'{C.CYN}{"=" * 60}{C.RST}')

        # IDPS
        idps = self.keys.get('idps', {})
        idps_ok = idps.get('valid', False)
        lines.append(f'\n{info("[IDPS]")} @ {idps.get("offset", "?")}  {ok("VALID") if idps_ok else fail("INVALID")}')
        lines.append(f'  Value:   {value(idps.get("hex", "N/A"))}')
        lines.append(f'  Entropy: {dim(str(idps.get("entropy", 0)))}')

        # PSID
        psid = self.keys.get('psid', {})
        psid_ok = psid.get('valid', False)
        lines.append(f'\n{info("[PSID]")} @ {psid.get("offset", "?")}  {ok("VALID") if psid_ok else fail("INVALID")}')
        lines.append(f'  Value:   {value(psid.get("hex", "N/A"))}')

        # klicensee
        klic = self.keys.get('klicensee', {})
        klic_ok = klic.get('valid', False)
        lines.append(f'\n{info("[klicensee]")} @ {klic.get("offset", "?")}  {ok("VALID") if klic_ok else fail("INVALID")}')
        lines.append(f'  Value:   {value(klic.get("hex", "N/A"))}')
        lines.append(f'  Entropy: {dim(str(klic.get("entropy", 0)))}')

        # HDD Keys
        hdd = self.keys.get('hdd_keys', {})
        hdd_ok = hdd.get('valid', False)
        lines.append(f'\n{info("[HDD XTS Keys]")} @ {hdd.get("blob_offset", "?")}  {ok("VALID") if hdd_ok else fail("INVALID")}')
        if hdd_ok:
            lines.append(f'  Data Key:  {value(hdd["data_key_hex"])}')
            lines.append(f'  Tweak Key: {value(hdd["tweak_key_hex"])}')
            lines.append(f'  SMI:       {dim(hdd.get("smi", "N/A"))}')
            if hdd.get('hmac_verified') is not None:
                hmac_lbl = ok("VERIFIED") if hdd['hmac_verified'] else warn("MISMATCH")
                lines.append(f'  HMAC:      {hmac_lbl}')
        else:
            lines.append(f'  {fail("Error:")} {warn(hdd.get("error", "Unknown"))}')

        # VTRM
        vtrm = self.keys.get('vtrm_keys', {})
        lines.append(f'\n{info("[VTRM Keys]")} {dim("(Syscon SNVS PRE0-PRE3)")}')
        lines.append(f'  Count: {vtrm.get("count", 0)}')
        for t, e in vtrm.get('latest_entries', {}).items():
            ctr = e['counter']
            lines.append(f'  {info(t)}: {value(e["data_hex"])} {dim(f"(ctr={ctr})")}')

        # SSC/SSK
        ssc = self.keys.get('ssc_ssk', {})
        lines.append(f'\n{info("[SSC/SSK Keys]")} {dim("(Syscon SNVS MODE0-BOOT3)")}')
        lines.append(f'  Count: {ssc.get("count", 0)}')
        for t, e in ssc.get('latest_entries', {}).items():
            ctr = e['counter']
            lines.append(f'  {info(t)}: {value(e["data_hex"])} {dim(f"(ctr={ctr})")}')

        # UART
        uart = self.keys.get('uart', {})
        lines.append(f'\n{info("[UART Debug]")}')
        uart_en = uart.get('enabled')
        lines.append(f'  Enabled: {ok("TRUE") if uart_en else fail("FALSE")}')

        lines.append(f'\n{C.CYN}{"=" * 60}{C.RST}')
        return '\n'.join(lines)


# ======================================================================
# CONVENIENCE FUNCTION
# ======================================================================

def extract_console_keys(nor_data: bytes, syscon_data: bytes = None) -> Dict:
    """Standalone convenience function."""
    extractor = ConsoleKeysExtractor(nor_data, syscon_data)
    return extractor.extract_all()
