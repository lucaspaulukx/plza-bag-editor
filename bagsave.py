import struct
from enum import Enum


class BagFlagID(Enum):
    IsNew = 0
    IsFavorite = 1
    IsGet = 2
    IsFriendlyShopNew = 3
    IsHaveMegaStone = 4
    IDCount = 5
    Count = 8


class FieldPocket(Enum):
    FIELDPCOKET_RECOVERY = 0  # Assuming this is the value based on context
    FIELDPCOKET_IMPORTANT = 1  # Assuming this is the value based on context
    MAX = 16  # Assuming based on the bit field size


class BagEntry:
    def __init__(self):
        self.category = -1
        self.quantity = 0
        self.flags = 0
        self.reserve = bytes(4)

    @classmethod
    def from_bytes(cls, data):
        if len(data) != 16:
            raise ValueError(f"BagEntry requires 16 bytes, got {len(data)}")

        entry = cls()
        entry.category, entry.quantity, entry.flags = struct.unpack('<i I B', data[:9])
        entry.reserve = data[9:13]
        return entry

    def get_flag(self, flag_id):
        return bool(self.flags & (1 << flag_id.value))

    def set_flag(self, flag_id, value):
        if value:
            self.flags |= (1 << flag_id.value)
        else:
            self.flags &= ~(1 << flag_id.value)

    def to_bytes(self):
        return struct.pack('<i I B', self.category, self.quantity, self.flags) + self.reserve + bytes(3)

    def __str__(self):
        flags_str = []
        for flag in BagFlagID:
            if flag.value < 8 and self.get_flag(flag):
                flags_str.append(flag.name)
        return f"BagEntry(category={self.category}, quantity={self.quantity}, flags=[{', '.join(flags_str)}])"


class BagReleaseCategory:
    def __init__(self):
        self.flags = 0
        self.padding = bytes(2)

    @classmethod
    def from_bytes(cls, data):
        if len(data) != 4:
            raise ValueError(f"BagReleaseCategory requires 4 bytes, got {len(data)}")

        release = cls()
        release.flags, = struct.unpack('<H', data[:2])
        release.padding = data[2:4]
        return release

    def get_flag(self, category):
        return bool(self.flags & (1 << category.value))

    def set_flag(self, category, value):
        if value:
            self.flags |= (1 << category.value)
        else:
            self.flags &= ~(1 << category.value)

    def to_bytes(self):
        return struct.pack('<H', self.flags) + self.padding

    def __str__(self):
        released = []
        for i in range(16):  # Based on FieldPocket.MAX = 16
            if self.flags & (1 << i):
                released.append(f"Category_{i}")
        return f"BagReleaseCategory(released=[{', '.join(released)}])"


class BagSave:
    ENTRY_CAPACITY = 3000
    TOTAL_SIZE = 48128

    def __init__(self):
        self.entries: list[BagEntry] = []
        self.release_category = BagReleaseCategory()
        self.reserve = bytes(124)

    @classmethod
    def from_bytes(cls, data):
        if len(data) != cls.TOTAL_SIZE:
            raise ValueError(f"BagSave requires {cls.TOTAL_SIZE} bytes, got {len(data)}")

        bag_save = cls()

        # Parse 3000 BagEntry objects (3000 * 16 = 48000 bytes)
        entry_size = 16
        for i in range(cls.ENTRY_CAPACITY):
            start = i * entry_size
            end = start + entry_size
            entry_data = data[start:end]
            bag_save.entries.append(BagEntry.from_bytes(entry_data))

        release_start = 48000
        release_data = data[release_start:release_start + 4]
        bag_save.release_category = BagReleaseCategory.from_bytes(release_data)

        reserve_start = 48004
        bag_save.reserve = data[reserve_start:reserve_start + 124]

        return bag_save

    def to_bytes(self):
        data = b''
        for entry in self.entries:
            data += entry.to_bytes()
        data += self.release_category.to_bytes()
        data += self.reserve
        return data

    def get_entry(self, item_id):
        if 0 <= item_id < len(self.entries):
            return self.entries[item_id]
        return None

    def set_entry(self, item_id, entry):
        if 0 <= item_id < len(self.entries):
            self.entries[item_id] = entry

    def is_release_category(self, category):
        return self.release_category.get_flag(category)

    def set_release_category(self, category, value=True):
        self.release_category.set_flag(category, value)

    def __str__(self):
        non_empty_entries = sum(1 for entry in self.entries if entry.quantity > 0)
        return f"BagSave(entries={non_empty_entries}/{self.ENTRY_CAPACITY} non-empty, {self.release_category})"
