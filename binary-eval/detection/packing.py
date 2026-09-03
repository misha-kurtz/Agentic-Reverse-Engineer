from dataclasses import dataclass, field

from detection.signatures import (
    KNOWN_UPX_SECTION_NAMES,
    KNOWN_PACKER_SECTION_NAMES,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_WRITE,
)


@dataclass
class PackingAssessment:
    detected: bool
    confidence: float
    family: str | None = None
    indicators: list[str] = field(default_factory=list)


def detect_packing(pe_data: dict) -> PackingAssessment:
    score: float = 0.0
    indicators: list[str] = []
    family: str | None = None

    sections = pe_data.get("sections", [])
    imports = pe_data.get("imports", [])
    markers = pe_data.get("packer_markers", [])

    # --------------------------------------------------
    # Packer-specific markers
    # --------------------------------------------------

    if "UPX!" in markers:
        score += 0.4
        family = "UPX"

        indicators.append(
            "UPX marker detected: UPX!"
        )

    # --------------------------------------------------
    # Section analysis
    # --------------------------------------------------

    for section in sections:
        name = section.get("name", "")
        entropy = section.get("entropy", 0.0)
        characteristics = section.get("characteristics", 0)
        virtual_size = section.get("virtual_size", 0)
        raw_size = section.get("raw_size", 0)

        normalized_name = name.lower()

        if name.upper() in KNOWN_UPX_SECTION_NAMES:
            score += 0.6
            family = "UPX"

            indicators.append(
                f"Known UPX section name detected: {name}"
            )

        elif normalized_name in KNOWN_PACKER_SECTION_NAMES:
            score += 0.4

            indicators.append(
                f"Suspicious packer-associated section name: {name}"
            )

        if entropy >= 7.2:
            score += 0.15

            indicators.append(
                f"High section entropy: {name} ({entropy:.2f})"
            )

        executable = bool(
            characteristics & IMAGE_SCN_MEM_EXECUTE
        )

        writable = bool(
            characteristics & IMAGE_SCN_MEM_WRITE
        )

        if executable and writable:
            score += 0.10

            indicators.append(
                f"Writable and executable section: {name}"
            )

        if (
            virtual_size > 0
            and raw_size == 0
            and executable
        ):
            score += 0.2
            indicators.append(
                f"Executable section has virtual data but no raw data: {name} "
                f"(virtual={virtual_size}, raw={raw_size})"
            )
        elif (
            raw_size > 0
            and virtual_size >= raw_size * 3
            and executable
        ): 
            score += 0.15
            indicators.append(
                f"Large virtual-to-raw size difference: {name} "
                f"(virtual={virtual_size}, raw={raw_size})"
            )

    # --------------------------------------------------
    # Entry-point section analysis
    # --------------------------------------------------

    entry_point_section = pe_data.get("entry_point_section")

    if entry_point_section:
        for section in sections:
            if section.get("name") != entry_point_section:
                continue

            entropy = section.get("entropy", 0.0)
            characteristics = section.get("characteristics", 0)

            executable = bool(
                characteristics & IMAGE_SCN_MEM_EXECUTE
            )

            writable = bool(
                characteristics & IMAGE_SCN_MEM_WRITE
            )

            if entropy >= 7.2 or (executable and writable):
                score += 0.15
                indicators.append(
                    f"Entry point is located in suspicious section: "
                    f"{entry_point_section}"
                )

            break

    # --------------------------------------------------
    # Import analysis
    # --------------------------------------------------

    import_count = sum(
        len(dll.get("imports", []))
        for dll in imports
    )

    if import_count <= 10:
        score += 0.15

        indicators.append(
            f"Sparse import table: {import_count} imports"
        )

    confidence = min(score, 1.0)

    return PackingAssessment(
        detected=confidence >= 0.5,
        confidence=confidence,
        family=family,
        indicators=indicators,
    )