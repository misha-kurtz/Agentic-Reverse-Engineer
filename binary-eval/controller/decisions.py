# binary-eval/controller/decisions.py

from enum import Enum


class RecoveryPolicy(Enum):
    AUTOMATED_UNPACKING = "automated_unpacking"
    AUTOMATED_DECRYPTION = "automated_decryption"
    NO_RECOVERY = "no_recovery"