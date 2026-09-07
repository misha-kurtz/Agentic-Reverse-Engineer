# binary-eval/controller/policy.py

from controller.decisions import RecoveryPolicy
from controller.state import AnalysisState


def choose_recovery_policy(
    state: AnalysisState,
) -> RecoveryPolicy:

    if state.packing_detected:
        return RecoveryPolicy.AUTOMATED_UNPACKING

    if state.encrypted_payload_suspected:
        return RecoveryPolicy.AUTOMATED_DECRYPTION

    return RecoveryPolicy.NO_RECOVERY