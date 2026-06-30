import os, struct
from ..utils.helpers import entropy
from ..utils.slb2 import extract_slb2
from ..utils.nor_defs import EAP_MGC_OFF, EAP_KEY_OFF as EAP_HDD_KEY_OFF, MAC_OFF

EAP_KEY_OFF = 0x024000
EAP_KEY_SIZE = 0x1000
EAP_SLOT2_OFF = EAP_KEY_OFF + EAP_KEY_SIZE
EAP_KEY_MD5_SIZE = 0x200

# HDD key derivation constants (from Wee Tools)
P_SEED_KEY = bytes.fromhex('E973A44C578757A73492625D2CE2D76B')
P_SEED = bytes.fromhex('DF0C2552DFC7F4F089B9D52DAA0E572A')
EAP_K1_SEED = bytes.fromhex('7A49D928D2243C9C4D6E1EA8F5B4E229317E0DCAD2ABE5C56D2540572FB4B6E3')
EAP_K2_SEED = bytes.fromhex('921CE9C8184C5DD476F4B5D3981F7E2F468193ED071E19FFFD66B693534689D6')
EAP_HDD_KEY_HEAD = b'SCE_EAP_HDD__KEY'
KEY_BLOB_ENC = bytes.fromhex('E073B691E177D39642DF2E1D583D0E9A5A49EDF72BE9412E2B433E51490CE973234B84F49E949F03727331D5456F4598F2EDE6D0C11483B84CE3283243D0DE9DC379E915301A805DFAEB292B30374C9BF1C59041509BF11D215C35D5C08E3330807C8229C930FAB88672C4CF7DACA881C323D72346CA07921DB806FC242A2ED1')
KEY_BLOB_SIG = bytes.fromhex('ED4F32C095847C6D3143EFFD61E7582F75F24465855C4E94DAF34885D8D03463')
KEY_BLOB_IV = bytes.fromhex('3286EA97F3E92C434E1DC170C9289003')
NEW_KEY_BLOB_ENC = bytes.fromhex('CFFDCB6ECAE612B7A30A9EDBD8F77E261D629DE5E6CA3F22F439211AC033884F4B5D7D16D0A6F65D3173A2586CF819C7C6F437444C1D9499F6EBC4145E0BBAABC1DE7C63ED1F5A1E1946358C7F181B1FAB6DAB31195D8E611A1CB81B9ACF8B38FF21029FAB568C7A1BCC3E2FBEB25B13F1AFD6A3599EEF09EAEBE32684FDDA29')
NEW_KEY_BLOB_SIG = bytes.fromhex('4798B78DD422601F26A32A1FEC5CAB8B256E50958E0B11A31D77DEE201D4D00E')
NEW_KEY_BLOB_IV = bytes.fromhex('462500ECC487F0A8C2F39511E020CC59')


def _is_empty(data):
    nv = sum(1 for b in data if b not in (0, 0xFF))
    return nv < 16


def _is_valid_key(data):
    if _is_empty(data):
        return False
    if entropy(data) < 7.0:
        return False
    return True


def _extract_from_emc(data, emc_start=0x4000, emc_end=0x64000):
    emc = bytes(data[emc_start:emc_end])
    try:
        slb2 = extract_slb2(emc)
        if slb2:
            for entry in slb2:
                raw_entry = entry.get("data", b"")
                if len(raw_entry) >= EAP_KEY_SIZE and _is_valid_key(raw_entry[:EAP_KEY_SIZE]):
                    return raw_entry[:EAP_KEY_SIZE]
    except Exception:
        pass
    return None


class EAPPatcher:
    def __init__(self, data):
        self.data = bytearray(data)

    def repair_eap_key(self):
        repairs = []

        slot1 = bytes(self.data[EAP_KEY_OFF:EAP_KEY_OFF + EAP_KEY_SIZE])
        slot2 = bytes(self.data[EAP_SLOT2_OFF:EAP_SLOT2_OFF + EAP_KEY_SIZE])

        s1_valid = _is_valid_key(slot1)
        s2_valid = _is_valid_key(slot2)

        if s1_valid and s2_valid:
            diff = sum(1 for a, b in zip(slot1, slot2) if a != b)
            if diff == 0:
                return repairs
            repairs.append("WARNING: EAP slots differ but both look valid")
            return repairs

        if not s1_valid and s2_valid:
            self.data[EAP_KEY_OFF:EAP_KEY_OFF + EAP_KEY_SIZE] = slot2
            repairs.append("EAP slot 1 restored from slot 2")
        elif s1_valid and not s2_valid:
            self.data[EAP_SLOT2_OFF:EAP_SLOT2_OFF + EAP_KEY_SIZE] = slot1
            repairs.append("EAP slot 2 restored from slot 1")
        else:
            recovered = _extract_from_emc(self.data)
            if recovered:
                self.data[EAP_KEY_OFF:EAP_KEY_OFF + EAP_KEY_SIZE] = recovered
                self.data[EAP_SLOT2_OFF:EAP_SLOT2_OFF + EAP_KEY_SIZE] = recovered
                repairs.append("EAP key recovered from EMC_IPL SLB2 entries")
            else:
                random_data = os.urandom(EAP_KEY_SIZE)
                self.data[EAP_KEY_OFF:EAP_KEY_OFF + EAP_KEY_SIZE] = random_data
                self.data[EAP_SLOT2_OFF:EAP_SLOT2_OFF + EAP_KEY_SIZE] = random_data
                repairs.append("Both EAP slots corrupt - generated new keys")

        return repairs

    def extract_hdd_keys(self, use_new_blob=False):
        try:
            from Crypto.Cipher import AES
            from Crypto.Hash import HMAC, SHA256
        except ImportError:
            return None, "pycryptodome not installed"

        from ..v2_features.hdd_analyzer import detect_eap_key_size

        magic = bytes(self.data[EAP_MGC_OFF:EAP_MGC_OFF+4])
        expected_magic = b'\xE5\xE5\xE5\x01'
        if magic != expected_magic:
            return None, f"EAP key magic mismatch: {magic.hex()} != {expected_magic.hex()}"

        eap_size = detect_eap_key_size(bytes(self.data))
        raw_key = bytes(self.data[EAP_HDD_KEY_OFF:EAP_HDD_KEY_OFF+eap_size])
        smi = struct.unpack_from("<I", self.data, 0x1C9034)[0]

        def aes_ecb(key, data):
            return AES.new(key, AES.MODE_ECB).encrypt(data)

        def aes_cbc(key, iv, data):
            return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

        def hmac_sha256(key, data):
            return HMAC.new(key=key, msg=data, digestmod=SHA256).digest()

        p_key = aes_ecb(P_SEED_KEY, P_SEED)
        key1 = aes_ecb(p_key, EAP_K1_SEED)
        key2 = aes_ecb(p_key, EAP_K2_SEED)

        wrapped = raw_key[:0x40] if eap_size < 0x60 else raw_key[:0x60]

        blob_enc = NEW_KEY_BLOB_ENC if use_new_blob else KEY_BLOB_ENC
        blob_sig = NEW_KEY_BLOB_SIG if use_new_blob else KEY_BLOB_SIG
        blob_iv = NEW_KEY_BLOB_IV if use_new_blob else KEY_BLOB_IV

        selected = key1
        sig = hmac_sha256(selected[0x10:0x20], blob_enc)
        if sig != blob_sig:
            selected = key2
            sig = hmac_sha256(selected[0x10:0x20], blob_enc)
            if sig != blob_sig:
                return None, "Key blob signature verification failed"

        blob = aes_cbc(selected[0x00:0x10], blob_iv, blob_enc)
        if not blob.startswith(EAP_HDD_KEY_HEAD):
            return None, "Decrypted blob missing expected header"

        blob_body = bytes.fromhex('BB6CD66DDC671FAC3664F7BF5049BAA8C4687904BC31CF4F2F4E9F89FA458793811745E7C7E80D460FAF2326550BD7E4D2A0A0D9729DE5D2117D70676F1D55748DC17CDF29C86A855F2AE9A1AD3E915F0000000000000000000000000000000000000000000000000000000000000000')
        full_blob = blob_body

        k_off = 0x60 if use_new_blob else 0x50
        key = full_blob[k_off:k_off+0x10]
        unwrapped = aes_cbc(key, b'\x00'*0x10, wrapped[:0x40])

        o = 0x10 if (smi == 0xFFFFFFFF or smi < 0x4000000) else 0x20
        unwrapped_dec = aes_cbc(full_blob[o:o+0x10], b'\x00'*0x10, unwrapped)
        if unwrapped_dec[0x10:0x20] != b'\x00'*0x10:
            unwrapped_dec = aes_cbc(full_blob[o:o+0x10], b'\x00'*0x10, wrapped[:0x10])

        kd_off = 0x40 if use_new_blob else 0x30
        key_data = full_blob[kd_off:kd_off+0x10]
        partition_key = hmac_sha256(unwrapped_dec[:0x10], key_data)

        tweak_key = partition_key[0x00:0x10]
        data_key = partition_key[0x10:0x20]

        result = {
            'data_key': data_key.hex(),
            'tweak_key': tweak_key.hex(),
            'use_new_blob': use_new_blob,
            'smi': f"0x{smi:08X}",
        }
        return result, None

    def get_hdd_key_summary(self):
        from ..v2_features.hdd_analyzer import detect_eap_key_size
        eap_size = detect_eap_key_size(bytes(self.data))
        hdd_key = bytes(self.data[EAP_HDD_KEY_OFF:EAP_HDD_KEY_OFF+eap_size])
        magic = bytes(self.data[EAP_MGC_OFF:EAP_MGC_OFF+4])
        expected = b'\xE5\xE5\xE5\x01'
        backup_hdd = bytes(self.data[EAP_HDD_KEY_OFF+0x3000:EAP_HDD_KEY_OFF+0x3000+eap_size])
        backup_magic = bytes(self.data[EAP_MGC_OFF+0x3000:EAP_MGC_OFF+0x3000+4])

        valid = magic == expected
        backup_valid = backup_magic == expected
        match = hdd_key == backup_hdd

        nz_primary = sum(1 for b in hdd_key if b not in (0, 0xFF))
        nz_backup = sum(1 for b in backup_hdd if b not in (0, 0xFF))

        return {
            'magic_ok': valid,
            'backup_magic_ok': backup_valid,
            'primary_match_backup': match,
            'primary_non_zero': nz_primary,
            'backup_non_zero': nz_backup,
            'mirrors_match': hdd_key == backup_hdd,
        }

    def get_data(self):
        return bytes(self.data)
