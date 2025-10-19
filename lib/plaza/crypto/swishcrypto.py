# * Adapted from: https://github.com/kwsch/PKHeX/blob/master/PKHeX.Core/Saves/Encryption/SwishCrypto/

import hashlib
from typing import List

from .scblock import SCBlock

class SwishCrypto:
    """MemeCrypto V2 - The Next Generation"""

    SIZE_HASH = hashlib.sha256().digest_size  # 0x20

    # Static hash bytes
    INTRO_HASH_BYTES = bytes([
        0x9E, 0xC9, 0x9C, 0xD7, 0x0E, 0xD3, 0x3C, 0x44, 0xFB, 0x93, 0x03, 0xDC, 0xEB, 0x39, 0xB4, 0x2A,
        0x19, 0x47, 0xE9, 0x63, 0x4B, 0xA2, 0x33, 0x44, 0x16, 0xBF, 0x82, 0xA2, 0xBA, 0x63, 0x55, 0xB6,
        0x3D, 0x9D, 0xF2, 0x4B, 0x5F, 0x7B, 0x6A, 0xB2, 0x62, 0x1D, 0xC2, 0x1B, 0x68, 0xE5, 0xC8, 0xB5,
        0x3A, 0x05, 0x90, 0x00, 0xE8, 0xA8, 0x10, 0x3D, 0xE2, 0xEC, 0xF0, 0x0C, 0xB2, 0xED, 0x4F, 0x6D,
    ])

    OUTRO_HASH_BYTES = bytes([
        0xD6, 0xC0, 0x1C, 0x59, 0x8B, 0xC8, 0xB8, 0xCB, 0x46, 0xE1, 0x53, 0xFC, 0x82, 0x8C, 0x75, 0x75,
        0x13, 0xE0, 0x45, 0xDF, 0x32, 0x69, 0x3C, 0x75, 0xF0, 0x59, 0xF8, 0xD9, 0xA2, 0x5F, 0xB2, 0x17,
        0xE0, 0x80, 0x52, 0xDB, 0xEA, 0x89, 0x73, 0x99, 0x75, 0x79, 0xAF, 0xCB, 0x2E, 0x80, 0x07, 0xE6,
        0xF1, 0x26, 0xE0, 0x03, 0x0A, 0xE6, 0x6F, 0xF6, 0x41, 0xBF, 0x7E, 0x59, 0xC2, 0xAE, 0x55, 0xFD,
    ])

    STATIC_XORPAD = bytes([
        0xA0, 0x92, 0xD1, 0x06, 0x07, 0xDB, 0x32, 0xA1, 0xAE, 0x01, 0xF5, 0xC5, 0x1E, 0x84, 0x4F, 0xE3,
        0x53, 0xCA, 0x37, 0xF4, 0xA7, 0xB0, 0x4D, 0xA0, 0x18, 0xB7, 0xC2, 0x97, 0xDA, 0x5F, 0x53, 0x2B,
        0x75, 0xFA, 0x48, 0x16, 0xF8, 0xD4, 0x8A, 0x6F, 0x61, 0x05, 0xF4, 0xE2, 0xFD, 0x04, 0xB5, 0xA3,
        0x0F, 0xFC, 0x44, 0x92, 0xCB, 0x32, 0xE6, 0x1B, 0xB9, 0xB1, 0x2E, 0x01, 0xB0, 0x56, 0x53, 0x36,
        0xD2, 0xD1, 0x50, 0x3D, 0xDE, 0x5B, 0x2E, 0x0E, 0x52, 0xFD, 0xDF, 0x2F, 0x7B, 0xCA, 0x63, 0x50,
        0xA4, 0x67, 0x5D, 0x23, 0x17, 0xC0, 0x52, 0xE1, 0xA6, 0x30, 0x7C, 0x2B, 0xB6, 0x70, 0x36, 0x5B,
        0x2A, 0x27, 0x69, 0x33, 0xF5, 0x63, 0x7B, 0x36, 0x3F, 0x26, 0x9B, 0xA3, 0xED, 0x7A, 0x53, 0x00,
        0xA4, 0x48, 0xB3, 0x50, 0x9E, 0x14, 0xA0, 0x52, 0xDE, 0x7E, 0x10, 0x2B, 0x1B, 0x77, 0x6E, 0,  # aligned to 0x80
    ])

    BLOCK_DATA_RATIO_ESTIMATE1 = 777  # bytes per block, on average (generous)
    BLOCK_DATA_RATIO_ESTIMATE2 = 555  # bytes per block, on average (stingy)

    @staticmethod
    def crypt_static_xorpad_bytes(data: bytearray) -> None:
        """Apply the static xorpad to the data in-place."""
        xp = SwishCrypto.STATIC_XORPAD
        size = len(xp) - 1  # 0x7F, not 0x80

        # Apply in chunks for efficiency
        iterations = (len(data) - 1) // size
        offset = 0

        for _ in range(iterations):
            # XOR current chunk with xorpad
            for i in range(len(xp)):
                if offset + i < len(data):
                    data[offset + i] ^= xp[i]
            offset += size

        # XOR the remainder
        for i in range(len(data) - offset):
            data[offset + i] ^= xp[i]

    @staticmethod
    def compute_hash(data: bytes) -> bytes:
        """Compute the SHA256 hash with intro and outro bytes."""
        sha = hashlib.sha256()
        sha.update(SwishCrypto.INTRO_HASH_BYTES)
        sha.update(data)
        sha.update(SwishCrypto.OUTRO_HASH_BYTES)
        return sha.digest()

    @staticmethod
    def get_is_hash_valid(data: bytes) -> bool:
        """Check if the file hash is valid."""
        if len(data) < SwishCrypto.SIZE_HASH:
            return False

        computed = SwishCrypto.compute_hash(data[:-SwishCrypto.SIZE_HASH])
        stored = data[-SwishCrypto.SIZE_HASH:]
        return computed == stored

    @staticmethod
    def decrypt(data: bytes) -> List[SCBlock]:
        """
        Decrypts the save data, then unpacks the blocks.

        Hash is assumed to be valid before calling this method.
        """
        # Convert to bytearray for in-place modification
        data_ba = bytearray(data)
        payload = data_ba[:-SwishCrypto.SIZE_HASH]
        SwishCrypto.crypt_static_xorpad_bytes(payload)
        return SwishCrypto.read_blocks(bytes(payload))

    @staticmethod
    def read_blocks(data: bytes) -> List[SCBlock]:
        """Read blocks from decrypted data."""
        result = []
        offset = 0

        while offset < len(data):
            block, offset = SCBlock.read_from_offset(data, offset)
            result.append(block)

        return result

    @staticmethod
    def encrypt(blocks: List[SCBlock]) -> bytes:
        """Encrypt the save data from blocks."""
        result = SwishCrypto.get_decrypted_raw_data(blocks)
        result_ba = bytearray(result)
        payload = result_ba[:-SwishCrypto.SIZE_HASH]
        SwishCrypto.crypt_static_xorpad_bytes(payload)
        result_ba[:-SwishCrypto.SIZE_HASH] = payload

        # Compute and set hash
        hash_bytes = SwishCrypto.compute_hash(bytes(payload))
        result_ba[-SwishCrypto.SIZE_HASH:] = hash_bytes

        return bytes(result_ba)

    @staticmethod
    def get_decrypted_raw_data(blocks: List[SCBlock]) -> bytes:
        """Get raw save data without the final xorpad layer."""
        result = bytearray()
        for block in blocks:
            result.extend(block.write_block())

        # Add space for hash
        result.extend(b'\x00' * SwishCrypto.SIZE_HASH)
        return bytes(result)