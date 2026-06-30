from ..utils.helpers import entropy
from ..utils.nor_defs import CID_REGIONS


def _region_empty(data, start, end):
    chunk = data[start:end]
    nv = sum(1 for b in chunk if b not in (0, 0xFF))
    return nv < 16, nv


def _region_healthy(data, start, end):
    chunk = data[start:end]
    nv = sum(1 for b in chunk if b not in (0, 0xFF))
    return nv > 32


class NVSPatcher:
    def __init__(self, data):
        self.data = bytearray(data)

    def analyze(self):
        info = {}
        pairs = [("1CA", "1CD"), ("1C9", "1CC")]
        for a_name, b_name in pairs:
            a_s, a_e = CID_REGIONS[a_name]
            b_s, b_e = CID_REGIONS[b_name]
            a_data = bytes(self.data[a_s:a_e])
            b_data = bytes(self.data[b_s:b_e])
            ma, nva = _region_empty(self.data, a_s, a_e)
            mb, nvb = _region_empty(self.data, b_s, b_e)
            ah = _region_healthy(self.data, a_s, a_e)
            bh = _region_healthy(self.data, b_s, b_e)
            match_pct = 0
            if len(a_data) > 0 and len(b_data) > 0:
                mlen = min(len(a_data), len(b_data))
                match = sum(1 for i in range(mlen) if a_data[i] == b_data[i])
                match_pct = match / mlen * 100
            info[a_name] = {"empty": ma, "non_zero": nva, "healthy": ah,
                            "match_with": b_name, "match_pct": match_pct, "entropy": entropy(a_data)}
            info[b_name] = {"empty": mb, "non_zero": nvb, "healthy": bh,
                            "match_with": a_name, "match_pct": match_pct, "entropy": entropy(b_data)}
        return info

    def _pair_regenerate(self, primary_pair, backup_pair):
        repairs = []
        for name in primary_pair:
            p_s, p_e = CID_REGIONS[name]
            e, _ = _region_empty(self.data, p_s, p_e)
            if e:
                t_size = p_e - p_s
                for alt in backup_pair:
                    a_s, a_e = CID_REGIONS[alt]
                    ah = _region_healthy(self.data, a_s, a_e)
                    if ah:
                        self.data[p_s:p_e] = bytes(self.data[a_s:a_e])[:t_size]
                        repairs.append(f"Regenerated {name} from {alt}")
                        break
                else:
                    a_s, a_e = CID_REGIONS[backup_pair[0]]
                    self.data[p_s:p_e] = bytes(self.data[a_s:a_e])[:t_size]
                    repairs.append(f"Copied {backup_pair[0]} -> {name} (forced)")
        return repairs

    def repair_cid(self):
        repairs = []
        cid_1ca = bytes(self.data[CID_REGIONS["1CA"][0]:CID_REGIONS["1CA"][1]])
        cid_1cd = bytes(self.data[CID_REGIONS["1CD"][0]:CID_REGIONS["1CD"][1]])

        e1, nv1 = _region_empty(self.data, *CID_REGIONS["1CA"])
        e2, nv2 = _region_empty(self.data, *CID_REGIONS["1CD"])
        h1 = _region_healthy(self.data, *CID_REGIONS["1CA"])
        h2 = _region_healthy(self.data, *CID_REGIONS["1CD"])

        if e1 and e2:
            alt = self._pair_regenerate(["1CA", "1CD"], ["1C9", "1CC"])
            repairs.extend(alt)
            return repairs

        if not e1 and not e2:
            if cid_1ca != cid_1cd:
                if h1 and not h2:
                    self.data[CID_REGIONS["1CD"][0]:CID_REGIONS["1CD"][1]] = cid_1ca
                    repairs.append("1CD corrupt - restored from 1CA")
                elif h2 and not h1:
                    self.data[CID_REGIONS["1CA"][0]:CID_REGIONS["1CA"][1]] = cid_1cd
                    repairs.append("1CA corrupt - restored from 1CD")
                else:
                    repairs.append("WARNING: 1CA != 1CD but both look valid")
            return repairs

        if e1 and not e2:
            self.data[CID_REGIONS["1CA"][0]:CID_REGIONS["1CA"][1]] = cid_1cd
            repairs.append("Repaired 1CA from 1CD backup")
        elif e2 and not e1:
            self.data[CID_REGIONS["1CD"][0]:CID_REGIONS["1CD"][1]] = cid_1ca
            repairs.append("Repaired 1CD from 1CA backup")
        return repairs

    def repair_unk_blocks(self):
        repairs = []
        uk1 = bytes(self.data[CID_REGIONS["1C9"][0]:CID_REGIONS["1C9"][1]])
        uk2 = bytes(self.data[CID_REGIONS["1CC"][0]:CID_REGIONS["1CC"][1]])

        e1, nv1 = _region_empty(self.data, *CID_REGIONS["1C9"])
        e2, nv2 = _region_empty(self.data, *CID_REGIONS["1CC"])
        h1 = _region_healthy(self.data, *CID_REGIONS["1C9"])
        h2 = _region_healthy(self.data, *CID_REGIONS["1CC"])

        if e1 and e2:
            alt = self._pair_regenerate(["1C9", "1CC"], ["1CA", "1CD"])
            repairs.extend(alt)
            return repairs

        if not e1 and not e2:
            if uk1 != uk2:
                if h1 and not h2:
                    t_size = CID_REGIONS["1CC"][1] - CID_REGIONS["1CC"][0]
                    self.data[CID_REGIONS["1CC"][0]:CID_REGIONS["1CC"][1]] = uk1[:t_size]
                    repairs.append("1CC corrupt - restored from 1C9")
                elif h2 and not h1:
                    self.data[CID_REGIONS["1C9"][0]:CID_REGIONS["1C9"][1]] = uk2
                    repairs.append("1C9 corrupt - restored from 1CC")
                else:
                    repairs.append("WARNING: 1C9 != 1CC but both look valid")
            return repairs

        if e1 and not e2:
            t_len = CID_REGIONS["1C9"][1] - CID_REGIONS["1C9"][0]
            self.data[CID_REGIONS["1C9"][0]:CID_REGIONS["1C9"][1]] = uk2[:t_len]
            repairs.append("Repaired 1C9 from 1CC backup")
        elif e2 and not e1:
            t_size = CID_REGIONS["1CC"][1] - CID_REGIONS["1CC"][0]
            self.data[CID_REGIONS["1CC"][0]:CID_REGIONS["1CC"][1]] = uk1[:t_size]
            repairs.append("Repaired 1CC from 1C9 backup")
        return repairs

    def sync_cid(self, source, target):
        pairs = {("1CA", "1CD"), ("1CD", "1CA"), ("1C9", "1CC"), ("1CC", "1C9")}
        if (source, target) not in pairs:
            return "Invalid pair: " + source + " -> " + target
        s_s, s_e = CID_REGIONS[source]
        t_s, t_e = CID_REGIONS[target]
        t_size = t_e - t_s
        src_data = bytes(self.data[s_s:s_e])[:t_size]
        self.data[t_s:t_e] = src_data
        return "Synced " + target + " from " + source

    def regenerate_nvs(self):
        repairs = []
        for name, (start, end) in CID_REGIONS.items():
            e, nv = _region_empty(self.data, start, end)
            if e:
                for alt_name, (alt_start, alt_end) in CID_REGIONS.items():
                    if alt_name == name:
                        continue
                    ah, _ = _region_healthy(self.data, alt_start, alt_end)
                    if ah:
                        t_size = end - start
                        self.data[start:end] = bytes(self.data[alt_start:alt_end])[:t_size]
                        repairs.append("Regenerated " + name + " from " + alt_name)
                        break
        return repairs

    def get_data(self):
        return bytes(self.data)
