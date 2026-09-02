from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass
class AnalysisState:
    sample_id: str
    sha256: str
    sample_variant: str

    guest_sample_path: PurePosixPath
    guest_static_dir: PurePosixPath

    presigned_url: str | None = None

    pe_metadata_path: PurePosixPath | None = None
    floss_output_path: PurePosixPath | None = None
    capa_output_path: PurePosixPath | None = None
    ghidra_output_dir: PurePosixPath | None = None

    sample_downloaded: bool = False
    sha256_verified: bool = False

    pe_analysis_complete: bool = False
    pe_upload_complete: bool = False

    floss_analysis_complete: bool = False
    floss_upload_complete: bool = False

    capa_analysis_complete: bool = False
    capa_upload_complete: bool = False

    ghidra_analysis_complete: bool = False
    ghidra_upload_complete: bool = False