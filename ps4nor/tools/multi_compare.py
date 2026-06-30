import os, hashlib, struct

SECTIONS = [
    ("SCE Header",      0x000000, 0x001000),
    ("ACT_SLOT",        0x001000, 0x001040),
    ("SB_A",            0x001040, 0x002000),
    ("SB_B",            0x002000, 0x003000),
    ("Main_MBR",        0x003000, 0x004000),
    ("EMC_IPL_A",       0x004000, 0x064000),
    ("EMC_IPL_B",       0x064000, 0x0C4000),
    ("EAP_KBL",         0x0C4000, 0x144000),
    ("Torus",           0x144000, 0x1C4000),
    ("NVS_Data",        0x1C4000, 0x1C9000),
    ("CID_Primary",     0x1C9000, 0x1C9200),
    ("EAP_Key",         0x1C9200, 0x1CA200),
    ("CID_Mirror",      0x1CA200, 0x1CC200),
    ("unallocated",     0x1CC200, 0x1CD000),
    ("NVS_MIR",         0x1CD000, 0x1D2C00),
    ("CORE_SWCH",       0x201000, 0x201400),
    ("NVS_Scrap",       0x5D0000, 0x5E0000),
    ("EAP_Key_B",       0x688000, 0x68A000),
]

SECTION_CAT = {
    "Boot Chain": ["SCE Header", "ACT_SLOT", "SB_A", "SB_B", "Main_MBR"],
    "Firmware": ["EMC_IPL_A", "EMC_IPL_B", "EAP_KBL", "Torus"],
    "NVS/CID": ["NVS_Data", "CID_Primary", "CID_Mirror", "NVS_MIR", "NVS_Scrap"],
    "Security": ["EAP_Key", "EAP_Key_B"],
    "System": ["CORE_SWCH", "unallocated"],
}


def section_md5(data, start, end):
    h = hashlib.md5(data[start:end]).hexdigest()
    return h


def multi_compare_menu(files_list=None):
    if not files_list:
        import glob
        dumps_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'dumps')
        if not os.path.isdir(dumps_dir):
            dumps_dir = 'dumps'
        pattern = input(f"Dumps directory [{dumps_dir}]: ").strip()
        if pattern:
            dumps_dir = pattern
        pat = input("File pattern [*.BIN]: ").strip() or "*.BIN"
        files_list = sorted(glob.glob(os.path.join(dumps_dir, pat)))
    if not files_list:
        return "No dump files found"
    if len(files_list) < 2:
        return "Need at least 2 files to compare"
    datas = []
    names = []
    for f in files_list:
        try:
            with open(f, 'rb') as fh:
                d = fh.read()
                if len(d) < 0x201000:
                    continue
                datas.append(d)
                names.append(os.path.basename(f))
        except:
            pass
    if len(datas) < 2:
        return "Not enough valid dumps"
    print(f"\nComparing {len(datas)} dumps:\n")
    for fn in names:
        print(f"  {fn}")
    print("\n" + "=" * 80)
    ref = datas[0]
    ref_name = names[0]
    for cat, sec_names in SECTION_CAT.items():
        print(f"\n{'=' * 40}")
        print(f"  {cat}")
        print(f"{'=' * 40}")
        for sec_name in sec_names:
            sec_info = [s for s in SECTIONS if s[0] == sec_name]
            if not sec_info:
                continue
            _, s, e = sec_info[0]
            ref_md5 = section_md5(ref, s, e)
            ref_size = e - s
            matches = 1
            mismatches = []
            for i in range(1, len(datas)):
                cur_md5 = section_md5(datas[i], s, e)
                if cur_md5 == ref_md5:
                    matches += 1
                else:
                    if ref_md5 != section_md5(ref, s, e):
                        mismatches.append((names[i], cur_md5))
            diff_byte = 0
            if mismatches:
                for i in range(1, len(datas)):
                    if section_md5(datas[i], s, e) != ref_md5:
                        for j in range(ref_size):
                            if datas[i][s+j] != ref[s+j]:
                                diff_byte += 1
            status = f"{matches}/{len(datas)} match"
            if mismatches:
                status += f", ~{diff_byte} bytes differ"
            if matches == len(datas):
                status = "IDENTICAL"
            print(f"  {sec_name:15s} {hex(s):10s} [{status}]")
    print(f"\n{'=' * 80}")
    return f"{'=' * 80}\nComparison complete: {len(datas)} dumps analyzed"
