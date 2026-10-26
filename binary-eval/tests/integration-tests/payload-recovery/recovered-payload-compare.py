import argparse
import hashlib
import os
import sys
import time

import pefile


def section_name(section):
    return section.Name.rstrip(b"\x00").decode(errors="replace")


def compare_value(label, manual, automated):
    match = manual == automated
    status = "PASS" if match else "DIFF"

    print(f"[{status}] {label}")
    print(f"       Manual:    {manual}")
    print(f"       Automated: {automated}")

    return match


def load_pe(path, label):
    print(f"\n[INFO] Loading {label}: {path}", flush=True)

    if not os.path.isfile(path):
        raise FileNotFoundError(f"PE file not found: {path}")

    print(f"[INFO] File size: {hex(os.path.getsize(path))} bytes", flush=True)

    start = time.perf_counter()
    pe = pefile.PE(path, fast_load=True)

    print(f"[PASS] PE headers loaded in {time.perf_counter() - start:.3f}s", flush=True)

    print("[INFO] Parsing import directory...", flush=True)
    start = time.perf_counter()

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )

    print(f"[PASS] Import directory parsed in {time.perf_counter() - start:.3f}s", flush=True)

    if pe.get_warnings():
        print(f"[WARNING] pefile reported {len(pe.get_warnings())} parsing warnings")

        for warning in pe.get_warnings():
            print(f"    {warning}")

    return pe


def compare_headers(manual, automated):
    print("\n========== PE HEADERS ==========")

    fields = [
        ("Machine", manual.FILE_HEADER.Machine, automated.FILE_HEADER.Machine),
        ("NumberOfSections", manual.FILE_HEADER.NumberOfSections, automated.FILE_HEADER.NumberOfSections),
        ("ImageBase", manual.OPTIONAL_HEADER.ImageBase, automated.OPTIONAL_HEADER.ImageBase),
        ("AddressOfEntryPoint", manual.OPTIONAL_HEADER.AddressOfEntryPoint, automated.OPTIONAL_HEADER.AddressOfEntryPoint),
        ("SizeOfImage", manual.OPTIONAL_HEADER.SizeOfImage, automated.OPTIONAL_HEADER.SizeOfImage),
        ("SizeOfHeaders", manual.OPTIONAL_HEADER.SizeOfHeaders, automated.OPTIONAL_HEADER.SizeOfHeaders),
        ("SectionAlignment", manual.OPTIONAL_HEADER.SectionAlignment, automated.OPTIONAL_HEADER.SectionAlignment),
        ("FileAlignment", manual.OPTIONAL_HEADER.FileAlignment, automated.OPTIONAL_HEADER.FileAlignment),
        ("Subsystem", manual.OPTIONAL_HEADER.Subsystem, automated.OPTIONAL_HEADER.Subsystem),
        ("DllCharacteristics", manual.OPTIONAL_HEADER.DllCharacteristics, automated.OPTIONAL_HEADER.DllCharacteristics)
    ]

    return [compare_value(name, hex(a), hex(b)) for name, a, b in fields]


def compare_sections(manual, automated):
    print("\n========== SECTION LAYOUT ==========")

    results = []

    for index in range(max(len(manual.sections), len(automated.sections))):
        if index >= len(manual.sections) or index >= len(automated.sections):
            print(f"[DIFF] Section {index}: Missing section")
            results.append(False)
            continue

        a = manual.sections[index]
        b = automated.sections[index]

        print(f"\n--- Section {index}: {section_name(a)} ---")

        fields = [
            ("Name", section_name(a), section_name(b)),
            ("VirtualAddress", hex(a.VirtualAddress), hex(b.VirtualAddress)),
            ("Misc_VirtualSize", hex(a.Misc_VirtualSize), hex(b.Misc_VirtualSize)),
            ("SizeOfRawData", hex(a.SizeOfRawData), hex(b.SizeOfRawData)),
            ("PointerToRawData", hex(a.PointerToRawData), hex(b.PointerToRawData)),
            ("Characteristics", hex(a.Characteristics), hex(b.Characteristics))
        ]

        for name, x, y in fields:
            results.append(compare_value(name, x, y))

    return results


def compare_section_data(manual, automated):
    print("\n========== SECTION HASHES / BYTE COMPARISON ==========")

    results = []

    for index in range(min(len(manual.sections), len(automated.sections))):
        a = manual.sections[index]
        b = automated.sections[index]

        name = section_name(a)

        data_a = a.get_data()
        data_b = b.get_data()

        hash_a = hashlib.sha256(data_a).hexdigest()
        hash_b = hashlib.sha256(data_b).hexdigest()

        print(f"\n--- Section {index}: {name} ---")

        results.append(compare_value("SHA256", hash_a, hash_b))

        common_length = min(len(data_a), len(data_b))
        max_length = max(len(data_a), len(data_b))

        differences = sum(x != y for x, y in zip(data_a, data_b))
        differences += abs(len(data_a) - len(data_b))

        matching = max_length - differences
        percentage = (matching / max_length * 100) if max_length else 100.0

        print(f"Matching bytes: {matching}/{max_length} ({percentage:.4f}%)")
        print(f"Differing bytes: {differences}")

        if differences:
            first_difference = next((i for i, (x, y) in enumerate(zip(data_a, data_b)) if x != y), None)

            if first_difference is not None:
                rva_a = a.VirtualAddress + first_difference
                rva_b = b.VirtualAddress + first_difference

                print(f"First differing manual RVA:    {hex(rva_a)}")
                print(f"First differing automated RVA: {hex(rva_b)}")
                print(f"Manual byte:    {hex(data_a[first_difference])}")
                print(f"Automated byte: {hex(data_b[first_difference])}")
            else:
                print(f"First difference occurs after common length: {hex(common_length)}")

        results.append(differences == 0)

    return results


def compare_entry_point(manual, automated):
    print("\n========== ENTRY POINT ==========")

    oep_a = manual.OPTIONAL_HEADER.AddressOfEntryPoint
    oep_b = automated.OPTIONAL_HEADER.AddressOfEntryPoint

    results = [compare_value("OEP RVA", hex(oep_a), hex(oep_b))]

    code_a = manual.get_data(oep_a, 0x100)
    code_b = automated.get_data(oep_b, 0x100)

    results.append(compare_value("OEP first 0x100 bytes", code_a.hex(" "), code_b.hex(" ")))

    return results


def get_imports(pe):
    imports = {}

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace").lower()

        functions = []

        for imp in entry.imports:
            name = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
            functions.append((name, imp.address - pe.OPTIONAL_HEADER.ImageBase))

        imports.setdefault(dll, []).extend(functions)

    for dll in imports:
        imports[dll].sort()

    return imports


def compare_imports(manual, automated):
    print("\n========== IMPORT TABLE ==========")

    imports_a = get_imports(manual)
    imports_b = get_imports(automated)

    results = []

    all_dlls = sorted(set(imports_a) | set(imports_b))

    results.append(compare_value("Imported DLL count", len(imports_a), len(imports_b)))

    for dll in all_dlls:
        a = imports_a.get(dll, [])
        b = imports_b.get(dll, [])

        print(f"\n--- {dll} ---")

        results.append(compare_value("Function count", len(a), len(b)))
        results.append(compare_value("Functions / IAT RVAs", a, b))

    return results


def compare_directories(manual, automated):
    print("\n========== DATA DIRECTORIES ==========")

    results = []

    dirs_a = manual.OPTIONAL_HEADER.DATA_DIRECTORY
    dirs_b = automated.OPTIONAL_HEADER.DATA_DIRECTORY

    for index in range(max(len(dirs_a), len(dirs_b))):
        if index >= len(dirs_a) or index >= len(dirs_b):
            print(f"[DIFF] Directory {index}: Missing directory")
            results.append(False)
            continue

        a = dirs_a[index]
        b = dirs_b[index]

        name = pefile.DIRECTORY_ENTRY.get(index, f"Directory_{index}")

        print(f"\n--- {name} ---")

        results.append(compare_value("RVA", hex(a.VirtualAddress), hex(b.VirtualAddress)))
        results.append(compare_value("Size", hex(a.Size), hex(b.Size)))

    return results


def compare_entropy(manual, automated):
    print("\n========== SECTION ENTROPY ==========")

    results = []

    for index in range(min(len(manual.sections), len(automated.sections))):
        a = manual.sections[index]
        b = automated.sections[index]

        entropy_a = a.get_entropy()
        entropy_b = b.get_entropy()

        difference = abs(entropy_a - entropy_b)

        print(f"\n--- {section_name(a)} ---")
        print(f"Manual entropy:    {entropy_a:.4f}")
        print(f"Automated entropy: {entropy_b:.4f}")
        print(f"Difference:        {difference:.4f}")

        results.append(difference < 0.01)

    return results


def main():
    parser = argparse.ArgumentParser(description="Compare manually and automatically reconstructed PE files.")

    parser.add_argument("manual", help="Path to manually reconstructed PE")
    parser.add_argument("automated", help="Path to automatically reconstructed PE")

    args = parser.parse_args()

    print("\n==============================================", flush=True)
    print("       PE RECONSTRUCTION VALIDATION", flush=True)
    print("==============================================", flush=True)

    print(f"[INFO] Python executable: {sys.executable}", flush=True)
    print(f"[INFO] Working directory: {os.getcwd()}", flush=True)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    manual_path = args.manual if os.path.isabs(args.manual) else os.path.join(script_dir, args.manual)
    automated_path = args.automated if os.path.isabs(args.automated) else os.path.join(script_dir, args.automated)

    manual = None
    automated = None

    try:
        manual = load_pe(manual_path, "manual PE")
        automated = load_pe(automated_path, "automated PE")

        results = []

        stages = [
            ("PE headers", compare_headers),
            ("Section layout", compare_sections),
            ("Section hashes and bytes", compare_section_data),
            ("Entry point", compare_entry_point),
            ("Imports", compare_imports),
            ("Data directories", compare_directories),
            ("Section entropy", compare_entropy)
        ]

        for name, function in stages:
            print(f"\n[INFO] Starting validation: {name}", flush=True)

            start = time.perf_counter()
            stage_results = function(manual, automated)

            results.extend(stage_results)

            print(f"[INFO] Completed {name} in {time.perf_counter() - start:.3f}s", flush=True)

        passed = sum(results)
        total = len(results)

        print("\n==============================================")
        print("                SUMMARY")
        print("==============================================")

        print(f"Passed checks: {passed}/{total}")
        print(f"Failed checks: {total - passed}")
        print(f"Match percentage: {(passed / total * 100) if total else 0:.2f}%")

        if all(results):
            print("\n[PASS] Reconstructed PE files match across all checks.")
        else:
            print("\n[WARNING] Differences detected between reconstructed PE files.")

    except Exception as exc:
        print(f"\n[ERROR] {type(exc).__name__}: {exc}", flush=True)
        raise

    finally:
        if manual is not None:
            manual.close()

        if automated is not None:
            automated.close()


if __name__ == "__main__":
    main()

