# binary-eval/workflows/payload_recovery/recovery_entry.py

'''
Payload Recovery Entry Point on Windows VM

Executed inside the Windows VM to invoke deterministic payload recovery.

1. Receive the recovery method and protected executable path.
2. Initialize CDB.
3. Invoke RuntimeUnpacker or RuntimeDecryptor.
4. Generate recovered.bin.
5. Generate recovery_result.json.
'''

# binary-eval/workflows/payload_recovery/recovery_entry.py

import argparse
import hashlib
import json
import shutil
import traceback

from pathlib import Path

from runners.debugger import CdbDebugger
from workflows.payload_recovery.runtime_unpack import RuntimeUnpacker
from workflows.payload_recovery.runtime_decrypt import RuntimeDecryptor


'''
Payload Recovery Entry Point on Windows VM

Purpose:
    Execute the deterministic payload recovery procedure selected by
    AnalysisController using the existing runtime payload recovery implementations.

Responsibilities:
    1. Receive the controller-selected payload recovery policy and protected executable.
    2. Validate the protected executable and calculate its SHA-256.
    3. Initialize ConsoleDbg using the configured debugger executable.
    4. Invoke RuntimeUnpacker or RuntimeDecryptor according to the policy.
    5. Validate the reconstructed executable returned by the recovery workflow.
    6. Save the reconstructed executable as recovered.bin.
    7. Calculate the recovered executable's SHA-256.
    8. Generate recovery_result.json containing recovery metadata.

'''


def calculate_sha256(file_path: Path) -> str:
    '''
    Calculate the SHA-256 hash of a file.
    '''

    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(0x100000), b""):
            digest.update(chunk)

    return digest.hexdigest()


def parse_arguments() -> argparse.Namespace:
    '''
    Parse recovery parameters provided by RecoveryDispatchRunner.
    '''

    parser = argparse.ArgumentParser(description="Deterministic payload recovery")

    parser.add_argument(
        "--method",
        required=True,
        choices=["AUTOMATED_UNPACKING", "AUTOMATED_DECRYPTION"],
    )

    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cdb-path", required=True, type=Path)

    return parser.parse_args()


def save_recovery_result(output_dir: Path, result_data: dict) -> Path:
    '''
    Save structured payload recovery metadata.
    '''

    result_path = output_dir / "recovery_result.json"
    temporary_path = output_dir / "recovery_result.json.tmp"

    with temporary_path.open("w", encoding="utf-8") as file:
        json.dump(result_data, file, indent=4)

    temporary_path.replace(result_path)

    return result_path


def execute_recovery(
    recovery_method: str,
    protected_path: Path,
    cdb_path: Path,
):
    '''
    Invoke the deterministic recovery implementation selected by the controller.
    '''

    with CdbDebugger(cdb_path) as debugger:
        if recovery_method == "AUTOMATED_UNPACKING":
            return RuntimeUnpacker(debugger).run(protected_path)

        if recovery_method == "AUTOMATED_DECRYPTION":
            return RuntimeDecryptor(debugger).run(protected_path)

        raise ValueError(f"Unsupported recovery method: {recovery_method}")


def normalize_recovery_result(
    recovery_method: str,
    protected_path: Path,
    protected_sha256: str,
    recovered_path: Path,
    recovered_sha256: str,
    result,
) -> dict:
    '''
    Normalize UPX and Hyperion recovery metadata into a common result structure.
    '''

    return {
        "recovery_method": recovery_method,
        "protected_sha256": protected_sha256,
        "recovered_sha256": recovered_sha256,
        "protected_path": str(protected_path),
        "recovered_path": str(recovered_path),
        "oep_rva": f"0x{result.oep_rva:X}",
        "iat_rva": f"0x{result.iat_rva:X}",
        "iat_size": f"0x{result.iat_size:X}",
        "iat_valid_thunks": result.iat_valid_thunks,
        "iat_invalid_thunks": result.iat_invalid_thunks,
        "recovery_successful": True,
    }


def main() -> None:
    '''
    Execute deterministic payload recovery and generate recovery metadata.
    '''

    args = parse_arguments()

    protected_path = args.input.resolve()
    output_dir = args.output.resolve()
    cdb_path = args.cdb_path.resolve()

    output_dir.mkdir(parents=True, exist_ok=True)

    result_path = output_dir / "recovery_result.json"
    recovered_path = output_dir / "recovered.bin"

    # Remove artifacts from previous recovery attempts.
    if result_path.exists():
        result_path.unlink()

    if recovered_path.exists():
        recovered_path.unlink()

    protected_sha256 = ""

    try:
        # Validate the protected executable.
        if not protected_path.is_file():
            raise FileNotFoundError(f"Protected executable not found: {protected_path}")

        if not cdb_path.is_file():
            raise FileNotFoundError(f"CDB executable not found: {cdb_path}")

        protected_sha256 = calculate_sha256(protected_path)

        # Execute the deterministic recovery implementation.
        result = execute_recovery(args.method, protected_path, cdb_path)

        # Validate the reconstructed executable.
        if result.reconstructed_path is None:
            raise RuntimeError("Recovery completed without producing a reconstructed executable")

        reconstructed_path = Path(result.reconstructed_path).resolve()

        if not reconstructed_path.is_file():
            raise FileNotFoundError(f"Reconstructed executable not found: {reconstructed_path}")

        if reconstructed_path.stat().st_size == 0:
            raise RuntimeError("Reconstructed executable is empty")

        # Save the recovered executable using the standardized output filename.
        if reconstructed_path != recovered_path:
            shutil.copy2(reconstructed_path, recovered_path)

        recovered_sha256 = calculate_sha256(recovered_path)

        # Normalize the recovery metadata.
        result_data = normalize_recovery_result(
            args.method,
            protected_path,
            protected_sha256,
            recovered_path,
            recovered_sha256,
            result,
        )

        save_recovery_result(output_dir, result_data)

        print(f"[recovery] Method: {args.method}")
        print(f"[recovery] Protected SHA-256: {protected_sha256}")
        print(f"[recovery] Recovered SHA-256: {recovered_sha256}")
        print(f"[recovery] Recovered executable: {recovered_path}")
        print(f"[recovery] OEP RVA: 0x{result.oep_rva:X}")
        print(f"[recovery] IAT RVA: 0x{result.iat_rva:X}")
        print("[recovery] Payload recovery completed successfully")

    except Exception as error:
        result_data = {
            "recovery_method": args.method,
            "protected_sha256": protected_sha256,
            "recovered_sha256": "",
            "protected_path": str(protected_path),
            "recovered_path": "",
            "oep_rva": "0x0",
            "iat_rva": "0x0",
            "iat_size": "0x0",
            "iat_valid_thunks": 0,
            "iat_invalid_thunks": 0,
            "recovery_successful": False,
            "error": str(error),
            "traceback": traceback.format_exc(),
        }

        save_recovery_result(output_dir, result_data)

        print(f"[recovery] Payload recovery failed: {error}")

        raise


if __name__ == "__main__":
    main()