import struct
from enum import Enum
from typing import Any

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