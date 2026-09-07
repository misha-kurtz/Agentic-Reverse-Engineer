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


def detect_packing(
    pe_data: dict,
    capa_data: dict | None = None,
    ghidra_metrics: dict | None = None,
) -> PackingAssessment:

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
        characteristics = section.get(
            "characteristics",
            0,
        )
        virtual_size = section.get(
            "virtual_size",
            0,
        )
        raw_size = section.get(
            "raw_size",
            0,
        )

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
                f"Suspicious packer-associated "
                f"section name: {name}"
            )

        if entropy >= 7.2:
            score += 0.15

            indicators.append(
                f"High section entropy: "
                f"{name} ({entropy:.2f})"
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
                f"Executable section has virtual data "
                f"but no raw data: {name} "
                f"(virtual={virtual_size}, raw={raw_size})"
            )

        elif (
            raw_size > 0
            and virtual_size >= raw_size * 3
            and executable
        ):
            score += 0.15

            indicators.append(
                f"Large virtual-to-raw size difference: "
                f"{name} "
                f"(virtual={virtual_size}, raw={raw_size})"
            )

    # --------------------------------------------------
    # Entry-point section analysis
    # --------------------------------------------------

    entry_point_section = pe_data.get(
        "entry_point_section"
    )

    if entry_point_section:
        for section in sections:
            if section.get("name") != entry_point_section:
                continue

            entropy = section.get(
                "entropy",
                0.0,
            )

            characteristics = section.get(
                "characteristics",
                0,
            )

            executable = bool(
                characteristics & IMAGE_SCN_MEM_EXECUTE
            )

            writable = bool(
                characteristics & IMAGE_SCN_MEM_WRITE
            )

            if (
                entropy >= 7.2
                or (executable and writable)
            ):
                score += 0.15

                indicators.append(
                    "Entry point is located in "
                    f"suspicious section: "
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
            f"Sparse import table: "
            f"{import_count} imports"
        )

    # --------------------------------------------------
    # capa analysis
    #
    # capa may identify packing through rules in the
    # anti-analysis/packer namespace. The internal packer
    # limitation rule is generated as a consequence of
    # those matches, so it is not scored separately.
    # --------------------------------------------------

    if capa_data is not None:

        capa_rules = capa_data.get("rules", {})

        capa_packer_detected = False
        capa_packer_family = None
        capa_packer_rule_names = []

        if isinstance(capa_rules, dict):

            for rule_name, rule_data in capa_rules.items():

                rule_meta = rule_data.get("meta", {})
                namespace = rule_meta.get("namespace", "")

                # Explicit capa packer rule
                if namespace.startswith("anti-analysis/packer"):

                    capa_packer_detected = True
                    capa_packer_rule_names.append(rule_name)

                    # Example:
                    # anti-analysis/packer/upx
                    namespace_parts = namespace.split("/")

                    if len(namespace_parts) >= 3:
                        capa_packer_family = (
                            namespace_parts[-1].upper()
                        )

        if capa_packer_detected:

            score += 0.20

            indicators.append(
                "capa identified packing via rule(s): "
                + ", ".join(capa_packer_rule_names)
            )

            # Use capa's family identification only when
            # another detector has not already identified it.
            if family is None and capa_packer_family:
                family = capa_packer_family

        # --------------------------------------------------
        # Weak semantic-degradation evidence
        # --------------------------------------------------

        if isinstance(capa_rules, dict):

            # Exclude internal capa bookkeeping/limitation
            # rules from the useful capability count.
            capability_rules = [
                rule_data
                for rule_data in capa_rules.values()
                if not rule_data
                    .get("meta", {})
                    .get("namespace", "")
                    .startswith("internal/")
            ]

            capa_rule_count = len(capability_rules)

            if capa_rule_count == 0:
                score += 0.10

                indicators.append(
                    "capa recovered no non-internal "
                    "capability rules"
                )

            elif capa_rule_count <= 3:
                score += 0.05

                indicators.append(
                    "Very few capa capability rules "
                    f"recovered: {capa_rule_count}"
                )

        # --------------------------------------------------
        # Ghidra analysis
        #
        # These metrics should be generated separately from
        # the Ghidra artifact directory and passed here.
        # --------------------------------------------------

        if ghidra_metrics is not None:

            function_count = ghidra_metrics.get(
                "function_count",
                0,
            )

            decompiled_function_count = (
                ghidra_metrics.get(
                    "decompiled_function_count",
                    0,
                )
            )

            decompilation_failure_count = (
                ghidra_metrics.get(
                    "decompilation_failure_count",
                    0,
                )
            )

            callgraph_edge_count = (
                ghidra_metrics.get(
                    "callgraph_edge_count",
                    0,
                )
            )

            # Extremely small recovered function set
            if function_count <= 5:
                score += 0.05

                indicators.append(
                    f"Very few Ghidra functions recovered: "
                    f"{function_count}"
                )

            # High decompilation failure ratio
            total_decompilation_attempts = (
                decompiled_function_count
                + decompilation_failure_count
            )

            if total_decompilation_attempts > 0:
                failure_ratio = (
                    decompilation_failure_count
                    / total_decompilation_attempts
                )

                if failure_ratio >= 0.50:
                    score += 0.10

                    indicators.append(
                        "High Ghidra decompilation failure "
                        f"ratio: {failure_ratio:.2f}"
                    )

            # Very sparse call graph
            if (
                function_count >= 5
                and callgraph_edge_count == 0
            ):
                score += 0.05

                indicators.append(
                    "Ghidra recovered functions but "
                    "no call graph edges"
                )

    # --------------------------------------------------
    # Final assessment
    # --------------------------------------------------

    confidence = min(score, 1.0)

    return PackingAssessment(
        detected=confidence >= 0.5,
        confidence=confidence,
        family=family,
        indicators=indicators,
    )