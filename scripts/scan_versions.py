import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ps4nor.v2_features.syscon_fw_db import _scan_syscon_version, read_efuse_bits

d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'syscon_donors')
samples = sorted([f for f in os.listdir(d) if f.endswith('.bin') and os.path.isfile(os.path.join(d, f))])

# Quick scan all files for version patterns + ARV
results = []
for name in samples:
    path = os.path.join(d, name)
    with open(path, 'rb') as f:
        data = f.read()
    ver = _scan_syscon_version(data)
    efuse = read_efuse_bits(data)
    arv = efuse.get('anti_rollback_version', -1)
    results.append((name, ver, arv))

# Group by ARV
arv_groups = {}
for name, ver, arv in results:
    arv_groups.setdefault(arv, []).append((name, ver))

print("ARV distribution:")
for arv in sorted(arv_groups.keys()):
    group = arv_groups[arv]
    count = len(group)
    # Show a few sample files and their version hints
    samples_str = ', '.join(f"{n}({v})" for n, v in group[:5])
    if count > 5:
        samples_str += f" ... +{count-5} more"
    print(f"  ARV {arv:>3d}: {count:>3d} files - {samples_str}")

print("\n\nFiles with ARV=0 (no efuse data):")
for name, ver, arv in results:
    if arv == 0:
        print(f"  {name}: hint={ver}")
