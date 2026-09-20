# binary-eval/detection/encryption.py

from dataclasses import dataclass, field


@dataclass
class EncryptionAssessment:
    suspected: bool
    confidence: float
    family: str | None = None

    crypto_behavior_detected: bool = False
    payload_concealment_detected: bool = False

    indicators: list[str] = field(default_factory=list)
    crypto_indicators: list[str] = field(default_factory=list)
    concealment_indicators: list[str] = field(default_factory=list)


def detect_encryption(
    pe_data: dict,
    capa_data: dict | None = None,
    ghidra_metrics: dict | None = None,
) -> EncryptionAssessment:

    score: float = 0.0

    # Supporting/weak evidence
    indicators: list[str] = []

    # Evidence of crypto
    crypto_indicators: list[str] = []

    # Evidence executable payload concealed
    concealment_indicators: list[str] = []

    family: str | None = None

    sections = pe_data.get("sections", [])
    imports = pe_data.get("imports", [])

    crypto_behavior_detected = False
    payload_concealment_evidence = False
    semantic_degradation = False

    runtime_linking_rules = []
    encoding_rules = []
    pe_loading_rules = []
    obfuscation_rules = []

    # --------------------------------------------------
    # PE structural analysis
    #
    # Encrypted/cryptor-protected payloads commonly
    # contain high-entropy data while retaining a small
    # loader/decryption stub.
    # --------------------------------------------------

    high_entropy_sections = []

    for section in sections:
        name = section.get("name", "")
        entropy = section.get("entropy", 0.0)

        if entropy >= 7.2:
            high_entropy_sections.append(
                (name, entropy)
            )

    if high_entropy_sections:

        score += 0.15

        for name, entropy in high_entropy_sections:
            indicators.append(
                f"High section entropy consistent with "
                f"encrypted/compressed data: "
                f"{name} ({entropy:.2f})"
            )

    # --------------------------------------------------
    # Import analysis
    #
    # A cryptor stub may expose only a small set of APIs
    # while resolving additional functionality at runtime.
    # --------------------------------------------------

    flattened_imports = []

    for dll in imports:
        dll_name = dll.get("dll", "")

        for imp in dll.get("imports", []):
            import_name = imp.get("name")

            if import_name:
                flattened_imports.append(
                    (
                        dll_name.lower(),
                        import_name.lower(),
                    )
                )

    import_count = len(flattened_imports)

    if import_count <= 10:
        score += 0.05

        indicators.append(
            f"Sparse import table consistent with "
            f"loader/decryption stub: "
            f"{import_count} imports"
        )

    # --------------------------------------------------
    # Loader/decryption-related imports
    # --------------------------------------------------

    imported_names = {
        import_name
        for _, import_name in flattened_imports
    }

    runtime_resolution_apis = {
        "getprocaddress",
        "loadlibrarya",
        "loadlibraryw",
        "loadlibraryexa",
        "loadlibraryexw",
        "ldrgetprocedureaddress",
        "ldrloaddll",
    }

    memory_apis = {
        "virtualalloc",
        "virtualallocex",
        "virtualprotect",
        "virtualprotectex",
        "ntallocatevirtualmemory",
        "ntprotectvirtualmemory",
    }

    runtime_resolution_matches = (
        imported_names
        & runtime_resolution_apis
    )

    memory_api_matches = (
        imported_names
        & memory_apis
    )

    if runtime_resolution_matches:
        score += 0.05

        indicators.append(
            "Runtime API resolution imports detected: "
            + ", ".join(
                sorted(runtime_resolution_matches)
            )
        )

    if memory_api_matches:
        score += 0.05

        indicators.append(
            "Runtime memory-management imports detected: "
            + ", ".join(
                sorted(memory_api_matches)
            )
        )

    # --------------------------------------------------
    # capa analysis
    #
    # Look for a combination of behaviors consistent with
    # a cryptor/decryption stub:
    #   - data decoding/decryption
    #   - runtime API resolution
    #   - PE parsing
    #   - section/protection handling
    #   - obfuscation
    # --------------------------------------------------

    if capa_data is not None:

        capa_rules = capa_data.get("rules", {})

        if isinstance(capa_rules, dict):


            for rule_name, rule_data in capa_rules.items():

                rule_meta = rule_data.get("meta", {})

                namespace = (
                    rule_meta.get("namespace", "")
                    or ""
                ).lower()

                normalized_name = rule_name.lower()

                # ------------------------------------------
                # Runtime API resolution
                # ------------------------------------------

                if (
                    namespace.startswith("linking/runtime-linking")
                    or "link function at runtime"
                    in normalized_name
                    or "link many functions at runtime"
                    in normalized_name
                ):
                    runtime_linking_rules.append(
                        rule_name
                    )

                # ------------------------------------------
                # Encoding / decryption behavior
                # ------------------------------------------

                if (
                    namespace.startswith(
                        "data-manipulation/encoding"
                    )
                    or "encode data using xor"
                    in normalized_name
                    or "decrypt"
                    in normalized_name
                    or "decode"
                    in normalized_name
                ):
                    encoding_rules.append(
                        rule_name
                    )

                # ------------------------------------------
                # PE reconstruction / loading behavior
                # ------------------------------------------

                if (
                    "parse pe header"
                    in normalized_name
                    or "inspect section memory permissions"
                    in normalized_name
                ):
                    pe_loading_rules.append(
                        rule_name
                    )

                # ------------------------------------------
                # Obfuscation behavior
                # ------------------------------------------

                if namespace.startswith(
                    "anti-analysis/obfuscation"
                ):
                    obfuscation_rules.append(
                        rule_name
                    )

            # Runtime linking is common in loaders, but is
            # insufficient by itself to imply encryption.
            if runtime_linking_rules:
                score += 0.05

                indicators.append(
                    "capa identified runtime API "
                    "resolution behavior: "
                    + ", ".join(runtime_linking_rules)
                )

            # Explicit encoding/decryption behavior is a
            # stronger encrypted-payload indicator.
            if encoding_rules:
                crypto_behavior_detected = True
                score += 0.05

                crypto_indicators.append(
                    "Cryptographic/data-encoding behavior detected: "
                    + ", ".join(encoding_rules)
                )

            # Parsing PE headers and inspecting section
            # permissions suggests runtime handling of an
            # embedded PE image.
            if pe_loading_rules:
                score += 0.10

                indicators.append(
                    "capa identified PE loading/"
                    "reconstruction behavior: "
                    + ", ".join(pe_loading_rules)
                )

            # Obfuscation is supporting evidence only.
            if obfuscation_rules:
                score += 0.10

                indicators.append(
                    "capa identified code/data "
                    "obfuscation behavior: "
                    + ", ".join(obfuscation_rules)
                )

    has_high_entropy = bool(high_entropy_sections)
    has_runtime_linking = bool(runtime_linking_rules)
    has_memory_management = bool(memory_api_matches)
    has_pe_loading = bool(pe_loading_rules)

    if (
        has_high_entropy
        and has_pe_loading
        and (
            has_runtime_linking
            or has_memory_management
        )
    ):
        payload_concealment_evidence = True
        score += 0.35

        concealment_indicators.append(
            "Combined encrypted-payload indicators: "
            "high entropy + PE loading/reconstruction + "
            "runtime loader behavior"
        )

    # --------------------------------------------------
    # Ghidra analysis
    #
    # A cryptor may expose only its loader/decryption
    # stub statically while hiding the original payload.
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

        # Small visible code footprint may indicate
        # only a loader/decryption stub is exposed.
        if function_count <= 5:
            semantic_degradation = True
            score += 0.05

            indicators.append(
                f"Very small Ghidra-visible code "
                f"footprint: {function_count} functions"
            )

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
                semantic_degradation = True
                score += 0.05

                indicators.append(
                    "High Ghidra decompilation failure "
                    f"ratio: {failure_ratio:.2f}"
                )

        if (
            function_count >= 3
            and callgraph_edge_count == 0
        ):
            score += 0.05

            indicators.append(
                "Ghidra recovered functions but "
                "no call graph edges"
            )


        if (
            not payload_concealment_evidence
            and has_high_entropy
            and semantic_degradation
            and (
                has_pe_loading
                or has_runtime_linking
                or has_memory_management
            )
        ):
            payload_concealment_evidence = True
            score += 0.35

            concealment_indicators.append(
                "Static semantic degradation combined with "
                "high entropy and loader behavior"
            )

    # --------------------------------------------------
    # Final assessment
    #
    # Generic encryption suspicion requires multiple
    # corroborating indicators. Family attribution is
    # separate from the generic detection result.
    # --------------------------------------------------

    confidence = min(score, 1.0)

    suspected = (
        confidence >= 0.5
        and payload_concealment_evidence
    )

    return EncryptionAssessment(
        suspected=suspected,
        confidence=confidence,
        family=family,
        crypto_behavior_detected=crypto_behavior_detected,
        payload_concealment_detected=payload_concealment_evidence,
        indicators=indicators,
        crypto_indicators=crypto_indicators,
        concealment_indicators=concealment_indicators,
    )