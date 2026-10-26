
import hashlib
import argparse
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

        print(f"\n--- {name} ---")

        results.append(compare_value("SHA256", hash_a, hash_b))

        common_length = min(len(data_a), len(data_b))
        max_length = max(len(data_a), len(data_b))

        differences = sum(data_a[i] != data_b[i] for i in range(common_length))
        differences += abs(len(data_a) - len(data_b))

        matching = max_length - differences
        percentage = (matching / max_length * 100) if max_length else 100.0

        print(f"Matching bytes: {matching}/{max_length} ({percentage:.4f}%)")
        print(f"Differing bytes: {differences}")

        if differences:
            for offset in range(common_length):
                if data_a[offset] != data_b[offset]:
                    rva = a.VirtualAddress + offset
                    print(f"First differing RVA: {hex(rva)}")
                    print(f"Manual byte:    {hex(data_a[offset])}")
                    print(f"Automated byte: {hex(data_b[offset])}")
                    break

        results.append(differences == 0)

    return results


def compare_entry_point(manual, automated):
    print("\n========== ENTRY POINT ==========")

    oep_a = manual.OPTIONAL_HEADER.AddressOfEntryPoint
    oep_b = automated.OPTIONAL_HEADER.AddressOfEntryPoint

    results = [compare_value("OEP RVA", hex(oep_a), hex(oep_b))]

    code_a = manual.get_data(oep_a, 0x100)
    code_b = automated.get_data(oep_b, 0x100)

    results.append(compare_value("OEP first 0x100 bytes", code_a.hex(), code_b.hex()))

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

        imports[dll] = sorted(functions)

    return imports


def compare_imports(manual, automated):
    print("\n========== IMPORT TABLE ==========")

    imports_a = get_imports(manual)
    imports_b = get_imports(automated)

    results = []

    for dll in sorted(set(imports_a) | set(imports_b)):
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

    for index in range(min(len(dirs_a), len(dirs_b))):
        a = dirs_a[index]
        b = dirs_b[index]

        name = a.name

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

        print(f"\n{section_name(a)}")
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

    print(f"\n[INFO] Loading manual PE: {args.manual}", flush=True)
    manual = pefile.PE(args.manual)
    print("[PASS] Manual PE loaded", flush=True)

    print(f"\n[INFO] Loading automated PE: {args.automated}", flush=True)
    automated = pefile.PE(args.automated)
    print("[PASS] Automated PE loaded", flush=True)

    results = []

    results += compare_headers(manual, automated)
    results += compare_sections(manual, automated)
    results += compare_section_data(manual, automated)
    results += compare_entry_point(manual, automated)
    results += compare_imports(manual, automated)
    results += compare_directories(manual, automated)
    results += compare_entropy(manual, automated)

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

    manual.close()
    automated.close()


if __name__ == "__main__":
    main()

