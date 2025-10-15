# * Adapted from: https://github.com/kwsch/PKHeX/blob/master/PKHeX.Core/Saves/Encryption/SwishCrypto/

import hashlib
import struct
from enum import Enum
from typing import List, Union, Any, Optional


class SCTypeCode(Enum):
    """Block type for a SCBlock."""
    NONE = 0
    BOOL1 = 1  # False?
    BOOL2 = 2  # True?
    BOOL3 = 3  # Either? (Array boolean type)
    OBJECT = 4
    ARRAY = 5
    BYTE = 8
    UINT16 = 9
    UINT32 = 10
    UINT64 = 11
    SBYTE = 12
    INT16 = 13
    INT32 = 14
    INT64 = 15
    SINGLE = 16
    DOUBLE = 17

    def is_boolean(self) -> bool:
        """Check if the type is a boolean type."""
        return self.value in (1, 2, 3)

    def get_type_size(self) -> int:
        """Gets the number of bytes occupied by a variable of a given type."""
        if self == SCTypeCode.BOOL3:
            return 1
        elif self in (SCTypeCode.BYTE, SCTypeCode.SBYTE):
            return 1
        elif self in (SCTypeCode.UINT16, SCTypeCode.INT16):
            return 2
        elif self in (SCTypeCode.UINT32, SCTypeCode.INT32, SCTypeCode.SINGLE):
            return 4
        elif self in (SCTypeCode.UINT64, SCTypeCode.INT64, SCTypeCode.DOUBLE):
            return 8
        else:
            raise ValueError(f"Unsupported type: {self}")

    def get_type(self) -> type:
        type_map = {
            SCTypeCode.BYTE: int,
            SCTypeCode.UINT16: int,
            SCTypeCode.UINT32: int,
            SCTypeCode.UINT64: int,
            SCTypeCode.SBYTE: int,
            SCTypeCode.INT16: int,
            SCTypeCode.INT32: int,
            SCTypeCode.INT64: int,
            SCTypeCode.SINGLE: float,
            SCTypeCode.DOUBLE: float,
        }
        if self in type_map:
            return type_map[self]
        raise ValueError(f"Unsupported type for GetType: {self}")

    def get_type_array(self) -> type:
        type_map = {
            SCTypeCode.BYTE: list,
            SCTypeCode.UINT16: list,
            SCTypeCode.UINT32: list,
            SCTypeCode.UINT64: list,
            SCTypeCode.SBYTE: list,
            SCTypeCode.INT16: list,
            SCTypeCode.INT32: list,
            SCTypeCode.INT64: list,
            SCTypeCode.SINGLE: list,
            SCTypeCode.DOUBLE: list,
        }
        if self in type_map:
            return type_map[self]
        raise ValueError(f"Unsupported type for GetTypeArray: {self}")

    def get_value(self, data: bytes) -> Any:
        """Gets the value from bytes."""
        if len(data) < self.get_type_size():
            raise ValueError(f"Insufficient data for type {self}")

        if self == SCTypeCode.BYTE:
            return data[0]
        elif self == SCTypeCode.UINT16:
            return struct.unpack('<H', data[:2])[0]
        elif self == SCTypeCode.UINT32:
            return struct.unpack('<I', data[:4])[0]
        elif self == SCTypeCode.UINT64:
            return struct.unpack('<Q', data[:8])[0]
        elif self == SCTypeCode.SBYTE:
            return struct.unpack('<b', bytes([data[0]]))[0]
        elif self == SCTypeCode.INT16:
            return struct.unpack('<h', data[:2])[0]
        elif self == SCTypeCode.INT32:
            return struct.unpack('<i', data[:4])[0]
        elif self == SCTypeCode.INT64:
            return struct.unpack('<q', data[:8])[0]
        elif self == SCTypeCode.SINGLE:
            return struct.unpack('<f', data[:4])[0]
        elif self == SCTypeCode.DOUBLE:
            return struct.unpack('<d', data[:8])[0]
        else:
            raise ValueError(f"Unsupported type for GetValue: {self}")

    def set_value(self, data: bytearray, value: Any) -> None:
        """Sets the value to bytes."""
        if self == SCTypeCode.BYTE:
            data[0] = value & 0xFF
        elif self == SCTypeCode.UINT16:
            struct.pack_into('<H', data, 0, value)
        elif self == SCTypeCode.UINT32:
            struct.pack_into('<I', data, 0, value)
        elif self == SCTypeCode.UINT64:
            struct.pack_into('<Q', data, 0, value)
        elif self == SCTypeCode.SBYTE:
            data[0] = value & 0xFF
        elif self == SCTypeCode.INT16:
            struct.pack_into('<h', data, 0, value)
        elif self == SCTypeCode.INT32:
            struct.pack_into('<i', data, 0, value)
        elif self == SCTypeCode.INT64:
            struct.pack_into('<q', data, 0, value)
        elif self == SCTypeCode.SINGLE:
            struct.pack_into('<f', data, 0, value)
        elif self == SCTypeCode.DOUBLE:
            struct.pack_into('<d', data, 0, value)
        else:
            raise ValueError(f"Unsupported type for SetValue: {self}")


class SCXorShift32:
    """
    Self-mutating value that returns a crypto value to be xor-ed with another (unaligned) byte stream.
    This implementation allows for yielding crypto bytes on demand.
    """

    def __init__(self, seed: int):
        self.counter = 0
        self.state = self._get_initial_state(seed)

    @staticmethod
    def _get_initial_state(state: int) -> int:
        """Get initial state based on seed."""
        pop_count = bin(state).count('1')
        for _ in range(pop_count):
            state = SCXorShift32._xorshift_advance(state)
        return state

    def next(self) -> int:
        """Gets a byte from the current state."""
        c = self.counter
        result = (self.state >> (c << 3)) & 0xFF
        if c == 3:
            self.state = self._xorshift_advance(self.state)
            self.counter = 0
        else:
            self.counter += 1
        return result

    def next32(self) -> int:
        """Gets a 32-bit integer from the current state."""
        return self.next() | (self.next() << 8) | (self.next() << 16) | (self.next() << 24)

    @staticmethod
    def _xorshift_advance(state: int) -> int:
        """Advance the xorshift state."""
        state ^= state << 2
        state &= 0xFFFFFFFF  # Keep it 32-bit
        state ^= state >> 15
        state ^= state << 13
        state &= 0xFFFFFFFF  # Keep it 32-bit
        return state


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


# noinspection DuplicatedCode
class SCBlock:
    """
    Block of Data obtained from a SwishCrypto encrypted block storage binary.
    """

    def __init__(self, key: int, block_type: SCTypeCode, data: bytes = b'', sub_type: SCTypeCode = SCTypeCode.NONE):
        self.key = key
        self.type = block_type
        self.raw = bytearray(data)
        self.sub_type = sub_type

    @property
    def data(self) -> bytearray:
        """Get the raw data as mutable bytearray."""
        return self.raw

    def change_boolean_type(self, value: SCTypeCode) -> None:
        """Changes the block's Boolean type."""
        if (self.type not in (SCTypeCode.BOOL1, SCTypeCode.BOOL2) or
                value not in (SCTypeCode.BOOL1, SCTypeCode.BOOL2)):
            raise ValueError(f"Cannot change {self.type} to {value}.")
        self.type = value

    def change_data(self, value: bytes) -> None:
        """Replaces the current data with a same-sized array."""
        if len(value) != len(self.raw):
            raise ValueError(f"Cannot change size of {self.type} block from {len(self.raw)} to {len(value)}.")
        self.raw[:] = value

    def has_value(self) -> bool:
        """Indicates if the block represents a single primitive value."""
        return self.type.value > SCTypeCode.ARRAY.value

    def get_value(self) -> Any:
        """Returns a boxed reference to a single primitive value."""
        if not self.has_value():
            raise ValueError("Block does not represent a single primitive value")
        return self.type.get_value(bytes(self.raw))

    def set_value(self, value: Any) -> None:
        """Sets a boxed primitive value to the block data."""
        if not self.has_value():
            raise ValueError("Block does not represent a single primitive value")
        self.type.set_value(self.raw, value)

    def clone(self) -> 'SCBlock':
        """Creates a deep copy of the block."""
        if len(self.raw) == 0:
            return SCBlock(self.key, self.type)
        clone_data = bytes(self.raw)
        if self.sub_type == SCTypeCode.NONE:
            return SCBlock(self.key, self.type, clone_data)
        return SCBlock(self.key, self.type, clone_data, self.sub_type)

    def write_block(self, write_key: bool = True) -> bytes:
        result = bytearray()
        xk = SCXorShift32(self.key)

        if write_key:
            result.extend(struct.pack('<I', self.key))

        # Write type
        result.append(self.type.value ^ xk.next())

        if self.type == SCTypeCode.OBJECT:
            # Write length
            length = len(self.raw) ^ xk.next32()
            result.extend(struct.pack('<I', length))
        elif self.type == SCTypeCode.ARRAY:
            # Write entry count and sub-type
            entries = len(self.raw) // self.sub_type.get_type_size()
            result.extend(struct.pack('<I', entries ^ xk.next32()))
            result.append(self.sub_type.value ^ xk.next())

        # Write data
        for byte in self.raw:
            result.append(byte ^ xk.next())

        return bytes(result)

    @staticmethod
    def get_total_length(data: bytes, key: Optional[int] = None, offset: int = 0) -> int:
        """
        Gets the total length of an encoded data block.
        """
        if key is None:
            key = struct.unpack('<I', data[:4])[0]
            offset = 4

        xk = SCXorShift32(key)

        # Read and decrypt type
        block_type = SCTypeCode(data[offset] ^ xk.next())
        offset += 1

        if block_type in (SCTypeCode.BOOL1, SCTypeCode.BOOL2, SCTypeCode.BOOL3):
            return offset
        elif block_type == SCTypeCode.OBJECT:
            # Read length
            if offset + 4 > len(data):
                raise ValueError("Insufficient data for object length")
            length = struct.unpack('<I', data[offset:offset + 4])[0] ^ xk.next32()
            offset += 4
            return offset + length
        elif block_type == SCTypeCode.ARRAY:
            # Read entry count and sub-type
            if offset + 4 > len(data):
                raise ValueError("Insufficient data for array entry count")
            count = struct.unpack('<I', data[offset:offset + 4])[0] ^ xk.next32()
            offset += 4

            if offset >= len(data):
                raise ValueError("Insufficient data for array sub-type")
            sub_type = SCTypeCode(data[offset] ^ xk.next())
            offset += 1

            element_size = sub_type.get_type_size()
            return offset + (element_size * count)
        else:
            # Single value storage
            element_size = block_type.get_type_size()
            return offset + element_size

    @staticmethod
    def read_from_offset(data: bytes, offset: int) -> tuple['SCBlock', int]:
        """Read a block from data starting at offset."""
        # Get key
        if offset + 4 > len(data):
            raise ValueError("Insufficient data for block key")
        key = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4
        return SCBlock._read_from_offset_with_key(data, key, offset)

    @staticmethod
    def _read_from_offset_with_key(data: bytes, key: int, offset: int) -> tuple['SCBlock', int]:
        xk = SCXorShift32(key)

        # Parse block type
        if offset >= len(data):
            raise ValueError("Insufficient data for block type")
        block_type = SCTypeCode(data[offset] ^ xk.next())
        offset += 1

        if block_type in (SCTypeCode.BOOL1, SCTypeCode.BOOL2, SCTypeCode.BOOL3):
            return SCBlock(key, block_type), offset
        elif block_type == SCTypeCode.OBJECT:
            # Read length
            if offset + 4 > len(data):
                raise ValueError("Insufficient data for object length")
            num_bytes = struct.unpack('<I', data[offset:offset + 4])[0] ^ xk.next32()
            offset += 4

            # Read and decrypt data
            if offset + num_bytes > len(data):
                raise ValueError("Insufficient data for object payload")
            arr = bytearray(data[offset:offset + num_bytes])
            offset += num_bytes

            for i in range(len(arr)):
                arr[i] ^= xk.next()

            return SCBlock(key, block_type, bytes(arr)), offset
        elif block_type == SCTypeCode.ARRAY:
            if offset + 4 > len(data):
                raise ValueError("Insufficient data for array entry count")
            num_entries = struct.unpack('<I', data[offset:offset + 4])[0] ^ xk.next32()
            offset += 4

            # Read sub-type
            if offset >= len(data):
                raise ValueError("Insufficient data for array sub-type")
            sub_type = SCTypeCode(data[offset] ^ xk.next())
            offset += 1

            # Read and decrypt data
            num_bytes = num_entries * sub_type.get_type_size()
            if offset + num_bytes > len(data):
                raise ValueError("Insufficient data for array payload")
            arr = bytearray(data[offset:offset + num_bytes])
            offset += num_bytes

            for i in range(len(arr)):
                arr[i] ^= xk.next()

            # Debug sanity check
            SCBlock._ensure_array_is_sane(sub_type, arr)

            return SCBlock(key, SCTypeCode.ARRAY, bytes(arr), sub_type), offset
        else:
            # Single value storage
            num_bytes = block_type.get_type_size()
            if offset + num_bytes > len(data):
                raise ValueError("Insufficient data for single value")
            arr = bytearray(data[offset:offset + num_bytes])
            offset += num_bytes

            for i in range(len(arr)):
                arr[i] ^= xk.next()

            return SCBlock(key, block_type, bytes(arr)), offset

    @staticmethod
    def _ensure_array_is_sane(sub_type: SCTypeCode, arr: bytearray) -> None:
        """Debug sanity check for array data."""
        if sub_type == SCTypeCode.BOOL3:
            # Check that all values are 0, 1, or 2
            for byte in arr:
                if byte not in (0, 1, 2):
                    print(f"Warning: BOOL3 array contains unexpected value: {byte}")
        else:
            # Should be a primitive type
            if sub_type.value <= SCTypeCode.ARRAY.value:
                print(f"Warning: Array sub-type {sub_type} is not a primitive type")

    def copy_from(self, other: 'SCBlock') -> None:
        """Merges the properties from other into this object."""
        if self.type.is_boolean():
            self.change_boolean_type(other.type)
        else:
            self.change_data(other.raw)

    def __repr__(self) -> str:
        if self.type == SCTypeCode.ARRAY:
            return f"SCBlock(key=0x{self.key:08X}, type={self.type}, sub_type={self.sub_type}, data_len={len(self.raw)})"
        else:
            return f"SCBlock(key=0x{self.key:08X}, type={self.type}, data_len={len(self.raw)})"


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