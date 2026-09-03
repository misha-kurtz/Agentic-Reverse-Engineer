# binary-eval/detection/signatures.py

KNOWN_UPX_SECTION_NAMES = {
    "UPX0",
    "UPX1",
    "UPX2",
}

KNOWN_UPX_MARKERS = {
    b"UPX!",
}

KNOWN_PACKER_SECTION_NAMES = {
    ".aspack",
    ".adata",
    ".packed",
    ".pack",
    ".petite",
    ".mpress1",
    ".mpress2",
}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000