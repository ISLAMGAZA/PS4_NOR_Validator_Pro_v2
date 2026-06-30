#!/usr/bin/env python3
"""
Syscon Deduplication Script:
1. Scans syscon_donors/ (excluding _archive/)
2. Groups files by MD5 hash
3. For each group, keeps the "best" name
4. Moves duplicates to syscon_donors/_archive/DEDUP_<md5>/
"""
import hashlib
import os
import sys
import shutil

SYSCON_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'syscon_donors')
ARCHIVE_DIR = os.path.join(SYSCON_DIR, '_archive')

def md5_file(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def score_name(name):
    """Higher score = better name to keep."""
    base = name.lower().replace('.bin', '')
    score = 0
    
    # Prefer -01 over -02
    if base.endswith('-01'):
        score += 100
    elif base.endswith('-02'):
        score += 50
    
    # Prefer shorter names
    score -= len(name) * 2
    
    # Penalize spaces
    if ' ' in name:
        score -= 30
    
    # Penalize special chars (non-alphanumeric, non-dash/underscore)
    specials = sum(1 for c in name if not c.isalnum() and c not in '-._')
    score -= specials * 10
    
    # Penalize names with letters after the number (like 155x, 176x)
    import re
    if re.search(r'\d+x\d*', base, re.IGNORECASE):
        score -= 20
    
    return score

def main():
    # Scan all .bin files (ignore subdirs)
    files = []
    for entry in os.listdir(SYSCON_DIR):
        fpath = os.path.join(SYSCON_DIR, entry)
        if os.path.isfile(fpath) and entry.lower().endswith('.bin'):
            files.append((entry, fpath))
    
    print(f"Found {len(files)} .bin files")
    
    # Compute MD5 for all
    md5_groups = {}
    for name, fpath in files:
        print(f"  MD5: {name} ...", end=' ')
        try:
            h = md5_file(fpath)
            md5_groups.setdefault(h, []).append((name, fpath))
            print(f"{h[:16]}...")
        except Exception as e:
            print(f"ERROR: {e}")
    
    # Dedup
    total_kept = 0
    total_moved = 0
    
    for md5, group in md5_groups.items():
        if len(group) == 1:
            total_kept += 1
            continue
        
        # Sort by score, best first
        group.sort(key=lambda x: score_name(x[0]), reverse=True)
        best_name, best_path = group[0]
        
        # Move rest to archive
        dedup_dir = os.path.join(ARCHIVE_DIR, f'DEDUP_{md5}')
        os.makedirs(dedup_dir, exist_ok=True)
        
        for dup_name, dup_path in group[1:]:
            dest = os.path.join(dedup_dir, dup_name)
            shutil.move(dup_path, dest)
            print(f"  DUP -> archive: {dup_name} (kept: {best_name})")
            total_moved += 1
        
        total_kept += 1
    
    print(f"\n=== Done ===")
    print(f"Kept: {total_kept} unique files")
    print(f"Moved: {total_moved} duplicates")
    print(f"Total unique MD5s: {len(md5_groups)}")

if __name__ == '__main__':
    main()
