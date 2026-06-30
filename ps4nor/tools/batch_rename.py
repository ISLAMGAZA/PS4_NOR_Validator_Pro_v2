import os, re, glob


def batch_rename_menu():
    print("\n=== Batch Rename Tool ===")
    pattern = input("File pattern (e.g. *.bin, *.BIN): ").strip()
    if not pattern:
        return "No pattern entered"
    files = sorted(glob.glob(pattern))
    if not files:
        return f"No files matching '{pattern}'"
    print(f"\nFound {len(files)} files:")
    for i, f in enumerate(files):
        print(f"  {i+1}. {os.path.basename(f)} ({os.path.getsize(f)} bytes)")
    print("\nRename modes:")
    print("  1. Add prefix")
    print("  2. Add suffix")
    print("  3. Replace text")
    print("  4. Number sequentially (e.g. dump_001.bin)")
    print("  5. Remove text")
    mode = input("\nSelect mode (1-5): ").strip()
    results = []
    if mode == "1":
        prefix = input("Prefix to add: ").strip()
        for f in files:
            d = os.path.dirname(f) or '.'
            name = os.path.basename(f)
            new = os.path.join(d, prefix + name)
            os.rename(f, new)
            results.append(f"{name} -> {prefix}{name}")
    elif mode == "2":
        suffix = input("Suffix to add (before extension): ").strip()
        for f in files:
            d = os.path.dirname(f) or '.'
            name = os.path.basename(f)
            root, ext = os.path.splitext(name)
            new = os.path.join(d, root + suffix + ext)
            os.rename(f, new)
            results.append(f"{name} -> {root}{suffix}{ext}")
    elif mode == "3":
        old = input("Text to replace: ").strip()
        new_text = input("Replace with: ").strip()
        for f in files:
            d = os.path.dirname(f) or '.'
            name = os.path.basename(f)
            new_name = name.replace(old, new_text)
            if new_name != name:
                new = os.path.join(d, new_name)
                os.rename(f, new)
                results.append(f"{name} -> {new_name}")
    elif mode == "4":
        prefix = input("Prefix (e.g. dump_): ").strip()
        start = input("Start number (default 1): ").strip()
        try:
            num = int(start) if start else 1
        except ValueError:
            num = 1
        digits = len(str(len(files)))
        for f in files:
            d = os.path.dirname(f) or '.'
            name = os.path.basename(f)
            _, ext = os.path.splitext(name)
            new_name = f"{prefix}{num:0{digits}d}{ext}"
            new = os.path.join(d, new_name)
            os.rename(f, new)
            results.append(f"{name} -> {new_name}")
            num += 1
    elif mode == "5":
        text = input("Text to remove: ").strip()
        for f in files:
            d = os.path.dirname(f) or '.'
            name = os.path.basename(f)
            new_name = name.replace(text, '')
            if new_name != name and new_name:
                new = os.path.join(d, new_name)
                os.rename(f, new)
                results.append(f"{name} -> {new_name}")
    else:
        return "Invalid mode"
    report = "\n".join(results) if results else "No files renamed"
    return report
