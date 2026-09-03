from dataclasses import dataclass
from pathlib import PurePosixPath

@dataclass
class AnalysisState:
    '''
    Represents the state of analysis for each malware sample.
    '''
    sample_id: str
    sha256: str
    sample_variant: str

    # Sample and Guest VM paths
    guest_sample_path: PurePosixPath
    guest_static_dir: PurePosixPath

    # Analysis and artifact output paths 
    pe_metadata_path: PurePosixPath | None = None
    floss_output_path: PurePosixPath | None = None
    capa_output_path: PurePosixPath | None = None
    ghidra_output_dir: PurePosixPath | None = None


    # Initial sample info
    presigned_url: str | None = None
    sample_downloaded: bool = False
    sha256_verified: bool = False

    # Static
    pe_analysis_complete: bool = False
    pe_upload_complete: bool = False
    floss_analysis_complete: bool = False
    floss_upload_complete: bool = False
    capa_analysis_complete: bool = False
    capa_upload_complete: bool = False
    ghidra_analysis_complete: bool = False
    ghidra_upload_complete: bool = False

    # Detection
    packing_detected: bool = False
    packing_family: str | None = None
    packing_confidence: float = 0.0
    encrypted_payload_suspected: bool = False
    encryption_confidence: float = 0.0

    # Dynamic
    dynamic_analysis_complete: bool = False

    # Recovery
    recovery_required: bool = False
    recovery_strategy: str | None = None
    recovery_attempted: bool = False
    recovery_successful: bool = False

    # Recovered sample info
    recovered_sha256: str | None = None
    recovered_sample_path: PurePosixPath | None = None
    recovered_static_dir: PurePosixPath | None = None

    # Recovered static artifact output paths
    recovered_pe_metadata_path: PurePosixPath | None = None
    recovered_floss_output_path: PurePosixPath | None = None
    recovered_capa_output_path: PurePosixPath | None = None
    recovered_ghidra_output_dir: PurePosixPath | None = None

    # Recovered static analysis flags
    recovered_pe_analysis_complete: bool = False
    recovered_pe_upload_complete: bool = False
    recovered_floss_analysis_complete: bool = False
    recovered_floss_upload_complete: bool = False
    recovered_capa_analysis_complete: bool = False
    recovered_capa_upload_complete: bool = False
    recovered_ghidra_analysis_complete: bool = False
    recovered_ghidra_upload_complete: bool = False
