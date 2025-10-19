from typing import Union

class FnvHash:
    """Fowler–Noll–Vo non-cryptographic hash"""

    # 64-bit constants
    K_FNV_PRIME_64 = 0x00000100000001B3
    K_OFFSET_BASIS_64 = 0xCBF29CE484222645

    # 32-bit constants
    K_FNV_PRIME_32 = 0x01000193
    K_OFFSET_BASIS_32 = 0x811C9DC5

    @staticmethod
    def hash_fnv1a_64(input_data: Union[str, bytes], hash_val: int = K_OFFSET_BASIS_64) -> int:
        """Gets the hash code of the input sequence via the alternative Fnv1 method."""
        if isinstance(input_data, str):
            input_data = input_data.encode('utf-8')  # Match C# char behavior

        for byte in input_data:
            hash_val ^= byte
            hash_val = (hash_val * FnvHash.K_FNV_PRIME_64) & 0xFFFFFFFFFFFFFFFF  # Keep it 64-bit
        return hash_val

    @staticmethod
    def hash_fnv1a_32(input_data: Union[str, bytes], hash_val: int = K_OFFSET_BASIS_32) -> int:
        """Gets the hash code of the input sequence via the alternative Fnv1 method."""
        if isinstance(input_data, str):
            input_data = input_data.encode('utf-8')

        for byte in input_data:
            hash_val ^= byte
            hash_val = (hash_val * FnvHash.K_FNV_PRIME_32) & 0xFFFFFFFF  # Keep it 32-bit
        return hash_val