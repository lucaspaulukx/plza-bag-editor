import struct
from enum import Enum
from typing import List


class PokedexKind(Enum):
    BASE_GAME = 0  # Assuming this is the main/primary dex


class DrawData:
    SIZE = 8

    def __init__(self):
        self.draw_form = 0
        self.draw_sex = 0
        self.draw_rare = 0
        self.draw_mg = 0
        self.draw_other = 0
        self.reserve = bytes(3)

    @classmethod
    def from_bytes(cls, data):
        """Parse DrawData from 8 bytes of data"""
        if len(data) != cls.SIZE:
            raise ValueError(f"DrawData requires {cls.SIZE} bytes, got {len(data)}")

        draw_data = cls()
        (draw_data.draw_form,
         draw_data.draw_sex,
         draw_data.draw_rare,
         draw_data.draw_mg,
         draw_data.draw_other) = struct.unpack('<B B B B B', data[:5])
        draw_data.reserve = data[5:8]
        return draw_data

    def to_bytes(self):
        """Convert DrawData back to bytes"""
        return struct.pack('<B B B B B',
                           self.draw_form,
                           self.draw_sex,
                           self.draw_rare,
                           self.draw_mg,
                           self.draw_other) + self.reserve

    def __str__(self):
        return (f"DrawData(form={self.draw_form}, sex={self.draw_sex}, "
                f"rare={self.draw_rare}, mega={self.draw_mg}, other={self.draw_other})")


class PokedexCoreData:
    SIZE = 132
    FORM_MAX = 8

    def __init__(self):
        # Flags
        self.capture_flg = 0  # 32-bit flag for capture status per form
        self.battle_flg = 0  # 32-bit flag for battle status per form
        self.language_flg = 0  # 16-bit flag for language

        # Status flags
        self.new_flg = 0  # New flag
        self.sex_flg = 0  # Gender flag
        self.rare_flg = 0  # 32-bit shiny flag per form
        self.mg_flg = 0  # Mega evolution flag
        self.oyabun_flg = 0  # Alpha/Boss capture flag

        # Reserve
        self.reserve = bytes(1)

        # Counters
        self.capture_num = [0] * self.FORM_MAX  # Capture count per form
        self.defeat_num = [0] * self.FORM_MAX  # Defeat count per form

        # DLC reserve
        self.dlc_reserve = bytes(7)

        # Display data
        self.draw_data_main = DrawData()

        # Additional display data reserve (space for 4 more DrawData)
        self.draw_data_reserve = bytes(32)  # 4 * 8 bytes

    @classmethod
    def from_bytes(cls, data):
        """Parse PokedexCoreData from 132 bytes of data"""
        if len(data) != cls.SIZE:
            raise ValueError(f"PokedexCoreData requires {cls.SIZE} bytes, got {len(data)}")

        core_data = cls()

        # Unpack flags (first 20 bytes)
        (core_data.capture_flg,
         core_data.battle_flg,
         core_data.language_flg,
         core_data.new_flg,
         core_data.sex_flg,
         core_data.rare_flg,
         core_data.mg_flg,
         core_data.oyabun_flg) = struct.unpack('<I I H B B I B B', data[:18])

        # Reserve (1 byte)
        core_data.reserve = data[20:21]

        # Capture numbers (8 bytes)
        core_data.capture_num = list(struct.unpack('<8B', data[21:29]))

        # Defeat numbers (8 bytes)
        core_data.defeat_num = list(struct.unpack('<8B', data[29:37]))

        # DLC reserve (7 bytes)
        core_data.dlc_reserve = data[37:44]

        # Draw data (8 bytes)
        core_data.draw_data_main = DrawData.from_bytes(data[44:52])

        # Draw data reserve (32 bytes)
        core_data.draw_data_reserve = data[52:84]

        return core_data

    def to_bytes(self):
        """Convert PokedexCoreData back to bytes"""
        data = b''

        # Pack flags
        data += struct.pack('<I I H B B I B B',
                            self.capture_flg,
                            self.battle_flg,
                            self.language_flg,
                            self.new_flg,
                            self.sex_flg,
                            self.rare_flg,
                            self.mg_flg,
                            self.oyabun_flg)

        # Reserve
        data += self.reserve

        # Capture and defeat numbers
        data += struct.pack('<8B', *self.capture_num)
        data += struct.pack('<8B', *self.defeat_num)

        # DLC reserve
        data += self.dlc_reserve

        # Draw data
        data += self.draw_data_main.to_bytes()

        # Draw data reserve
        data += self.draw_data_reserve

        # Pad to 132 bytes if needed
        if len(data) < self.SIZE:
            data += bytes(self.SIZE - len(data))

        return data

    def is_captured(self, form_index=0):
        """Check if a specific form is captured"""
        if 0 <= form_index < 32:  # 32 bits in the flag
            return bool(self.capture_flg & (1 << form_index))
        return False

    def set_captured(self, form_index=0, captured=True):
        """Set capture flag for a specific form"""
        if 0 <= form_index < 32:
            if captured:
                self.capture_flg |= (1 << form_index)
            else:
                self.capture_flg &= ~(1 << form_index)

    def is_battled(self, form_index=0):
        """Check if a specific form has been battled"""
        if 0 <= form_index < 32:
            return bool(self.battle_flg & (1 << form_index))
        return False

    def set_battled(self, form_index=0, battled=True):
        """Set battle flag for a specific form"""
        if 0 <= form_index < 32:
            if battled:
                self.battle_flg |= (1 << form_index)
            else:
                self.battle_flg &= ~(1 << form_index)

    def is_shiny(self, form_index=0):
        """Check if a specific form is shiny"""
        if 0 <= form_index < 32:
            return bool(self.rare_flg & (1 << form_index))
        return False

    def set_shiny(self, form_index=0, shiny=True):
        """Set shiny flag for a specific form"""
        if 0 <= form_index < 32:
            if shiny:
                self.rare_flg |= (1 << form_index)
            else:
                self.rare_flg &= ~(1 << form_index)

    def get_capture_count(self, form_index=0):
        """Get capture count for a specific form"""
        if 0 <= form_index < self.FORM_MAX:
            return self.capture_num[form_index]
        return 0

    def set_capture_count(self, form_index=0, count=0):
        """Set capture count for a specific form"""
        if 0 <= form_index < self.FORM_MAX:
            self.capture_num[form_index] = min(count, 255)  # uint8 max

    def get_defeat_count(self, form_index=0):
        """Get defeat count for a specific form"""
        if 0 <= form_index < self.FORM_MAX:
            return self.defeat_num[form_index]
        return 0

    def set_defeat_count(self, form_index=0, count=0):
        """Set defeat count for a specific form"""
        if 0 <= form_index < self.FORM_MAX:
            self.defeat_num[form_index] = min(count, 255)  # uint8 max

    def __str__(self):
        captured_forms = []
        for i in range(32):
            if self.is_captured(i):
                captured_forms.append(str(i))

        battled_forms = []
        for i in range(32):
            if self.is_battled(i):
                battled_forms.append(str(i))

        return (f"PokedexCoreData(captured_forms=[{', '.join(captured_forms)}], "
                f"battled_forms=[{', '.join(battled_forms)}], "
                f"new={self.new_flg}, shiny_flags=0x{self.rare_flg:08X}, "
                f"mega={self.mg_flg}, alpha={self.oyabun_flg})")


class PokedexData:
    DEV_NO_MAX = 1210  # 1010 + 200 as specified
    SIZE = 159848

    def __init__(self):
        self.pokedex_data = [PokedexCoreData() for _ in range(self.DEV_NO_MAX)]
        self.reserve = bytes(128)

    @classmethod
    def from_bytes(cls, data):
        """Parse PokedexData from 159848 bytes of data"""
        if len(data) != cls.SIZE:
            raise ValueError(f"PokedexData requires {cls.SIZE} bytes, got {len(data)}")

        pokedex_data = cls()

        # Parse all PokedexCoreData entries
        core_data_size = PokedexCoreData.SIZE
        for i in range(cls.DEV_NO_MAX):
            start = i * core_data_size
            end = start + core_data_size
            core_data_bytes = data[start:end]
            pokedex_data.pokedex_data[i] = PokedexCoreData.from_bytes(core_data_bytes)

        # Parse reserve (128 bytes at the end)
        reserve_start = cls.DEV_NO_MAX * core_data_size
        pokedex_data.reserve = data[reserve_start:reserve_start + 128]

        return pokedex_data

    def to_bytes(self):
        """Convert PokedexData back to bytes"""
        data = b''

        # Serialize all core data entries
        for core_data in self.pokedex_data:
            data += core_data.to_bytes()

        # Add reserve
        data += self.reserve

        return data

    def get_pokedex_data(self, dev_no):
        """Get PokedexCoreData for a specific Pokemon by development number"""
        if 0 <= dev_no < len(self.pokedex_data):
            return self.pokedex_data[dev_no]
        return None

    def set_pokedex_data(self, dev_no, core_data):
        """Set PokedexCoreData for a specific Pokemon by development number"""
        if 0 <= dev_no < len(self.pokedex_data):
            self.pokedex_data[dev_no] = core_data

    def get_captured_count(self):
        """Get total number of captured Pokemon (any form)"""
        count = 0
        for core_data in self.pokedex_data:
            if core_data.capture_flg != 0:  # Any form captured
                count += 1
        return count

    def get_shiny_count(self):
        """Get total number of shiny Pokemon (any form)"""
        count = 0
        for core_data in self.pokedex_data:
            if core_data.rare_flg != 0:  # Any form shiny
                count += 1
        return count

    def __str__(self):
        captured = self.get_captured_count()
        shiny = self.get_shiny_count()
        return f"PokedexData(entries={self.DEV_NO_MAX}, captured={captured}, shiny={shiny})"


class PokedexSaveDataAccessor:
    def __init__(self):
        self.data = PokedexData()

    @classmethod
    def from_bytes(cls, data):
        """Parse PokedexSaveDataAccessor from bytes"""
        accessor = cls()
        accessor.data = PokedexData.from_bytes(data)
        return accessor

    def to_bytes(self):
        """Convert to bytes"""
        return self.data.to_bytes()

    def set_pokedex_data(self, dev_no, core_data):
        """Set PokedexCoreData for a specific development number"""
        if 0 <= dev_no < self.data.DEV_NO_MAX:
            self.data.set_pokedex_data(dev_no, core_data)

    def get_pokedex_data(self, dev_no):
        """Get PokedexCoreData for a specific development number"""
        if 0 <= dev_no < self.data.DEV_NO_MAX:
            return self.data.get_pokedex_data(dev_no)
        return PokedexCoreData()  # Return empty data for out of range

    def get_pokedex_data_const(self, dev_no):
        """Get PokedexCoreData as const reference (same as get_pokedex_data in Python)"""
        return self.get_pokedex_data(dev_no)

    def get_draw_data(self, dev_no, kind=PokedexKind.BASE_GAME):
        """Get DrawData for a specific Pokemon and Pokedex kind"""
        core_data = self.get_pokedex_data(dev_no)
        if core_data:
            return core_data.draw_data_main  # Only Ikkaku is implemented
        return DrawData()

    def is_pokedex_data_out_of_range(self, dev_no):
        """Check if development number is out of range"""
        return dev_no < 0 or dev_no >= self.data.DEV_NO_MAX

    def get_completion_percentage(self):
        """Calculate completion percentage (any form captured counts)"""
        total_possible = self.data.DEV_NO_MAX
        captured = self.data.get_captured_count()
        return (captured / total_possible) * 100 if total_possible > 0 else 0

    def __str__(self):
        return str(self.data)
