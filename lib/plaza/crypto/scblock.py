import struct
from typing import Any, Optional

from .sctypecode import SCTypeCode
from .scxorshift import SCXorShift32

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

    # noinspection PyTypeChecker
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