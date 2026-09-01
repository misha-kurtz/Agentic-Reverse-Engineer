# Analysis state for current binary sample
# 
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AnalysisState:
    sample_id: str
    sha256: str
    presigned_url: str

    guest_sample_path: Path
    guest_static_dir: Path

    pe_metadata_path: Path | None = None

    sample_downloaded: bool = False
    sha256_verified: bool = False
    pe_analysis_complete: bool = False
    static_upload_complete: bool = False