import struct
from enum import Enum


class Gender(Enum):
    MALE = 0
    FEMALE = 1


class CoreData:
    SIZE = 120

    def __init__(self):
        # Basic info
        self.id = 0
        self.rom_code = 0
        self.sex = Gender.MALE.value
        self.padding1 = 0
        self.poke_language_id = 0

        # System info
        self.nex_unique_id = 0
        self.nex_principal_rom_id = 0

        # Character info
        self.name = [0] * 13  # 12 characters + null terminator (StrCode is uint16)
        self.player_icon_id = 0

        # Rank info
        self.member_rank = 0
        self.member_rank_exp = 0

        # Network info
        self.npln_user_id = bytes(29)
        self.is_npln_user_id_valid = 0

        # Personal info
        self.birthday_month = 0
        self.birthday_day = 0
        self.is_birthday_set = 0
        self.is_birthday_event_view = 0
        self.birthday_event_view_year = 0

        # Gameplay stats
        self.partner_walk_count = 0
        self.egg_hatch_count = 0
        self.player_hp = 0

        # Mega evolution
        self.mega_power = 0.0
        self.mega_evo_timer = 0.0

        # System flags
        self.illegal_egg_check_ver120 = 0

        # Padding
        self.padding2 = bytes(5)

    @classmethod
    def from_bytes(cls, data):
        """Parse CoreData from 120 bytes of data"""
        if len(data) != cls.SIZE:
            raise ValueError(f"CoreData requires {cls.SIZE} bytes, got {len(data)}")

        core_data = cls()

        # Unpack the binary data
        # First 8 bytes: ID, rom_code, sex, padding1, poke_language_id
        (core_data.id,
         core_data.rom_code,
         core_data.sex,
         core_data.padding1,
         core_data.poke_language_id) = struct.unpack('<I B B B B', data[:8])

        # Next 8 bytes: nex_unique_id
        core_data.nex_unique_id = struct.unpack('<Q', data[8:16])[0]

        # Name: 13 uint16 values (26 bytes)
        name_format = '<' + 'H' * 13
        core_data.name = list(struct.unpack(name_format, data[16:42]))

        # Player icon ID (4 bytes)
        core_data.player_icon_id = struct.unpack('<I', data[42:46])[0]

        # Next principal ROM ID (8 bytes)
        core_data.nex_principal_rom_id = struct.unpack('<Q', data[46:54])[0]

        # Member rank and exp packed in 4 bytes
        # member_rank: 8 bits, member_rank_exp: 24 bits
        packed_rank = struct.unpack('<I', data[54:58])[0]
        core_data.member_rank = packed_rank & 0xFF
        core_data.member_rank_exp = (packed_rank >> 8) & 0xFFFFFF

        # NPLN user ID (29 bytes) + validity flag (1 byte)
        core_data.npln_user_id = data[58:87]
        core_data.is_npln_user_id_valid = data[87]

        # Birthday (2 bytes)
        core_data.birthday_month = data[88]
        core_data.birthday_day = data[89]

        # Partner walk count (2 bytes)
        core_data.partner_walk_count = struct.unpack('<H', data[90:92])[0]

        # Padding2 (5 bytes)
        core_data.padding2 = data[92:97]

        # Illegal egg check (1 byte)
        core_data.illegal_egg_check_ver120 = data[97]

        # Egg hatch count (4 bytes)
        core_data.egg_hatch_count = struct.unpack('<I', data[98:102])[0]

        # Mega power and timer (8 bytes total)
        core_data.mega_power = struct.unpack('<f', data[102:106])[0]
        core_data.mega_evo_timer = struct.unpack('<f', data[106:110])[0]

        # Player HP (4 bytes)
        core_data.player_hp = struct.unpack('<I', data[110:114])[0]

        # Birthday flags (2 bytes)
        core_data.is_birthday_set = data[114]
        core_data.is_birthday_event_view = data[115]

        # Birthday event year (2 bytes)
        core_data.birthday_event_view_year = struct.unpack('<H', data[116:118])[0]

        # Last 2 bytes are padding
        return core_data

    def to_bytes(self):
        """Convert CoreData back to bytes"""
        data = b''

        # Pack first 8 bytes
        data += struct.pack('<I B B B B',
                            self.id,
                            self.rom_code,
                            self.sex,
                            self.padding1,
                            self.poke_language_id)

        # nex_unique_id
        data += struct.pack('<Q', self.nex_unique_id)

        # Name
        name_format = '<' + 'H' * 13
        data += struct.pack(name_format, *self.name)

        # Player icon ID
        data += struct.pack('<I', self.player_icon_id)

        # nex_principal_rom_id
        data += struct.pack('<Q', self.nex_principal_rom_id)

        # Pack member rank and exp
        packed_rank = (self.member_rank & 0xFF) | ((self.member_rank_exp & 0xFFFFFF) << 8)
        data += struct.pack('<I', packed_rank)

        # NPLN user ID and validity
        data += self.npln_user_id
        data += bytes([self.is_npln_user_id_valid])

        # Birthday
        data += bytes([self.birthday_month, self.birthday_day])

        # Partner walk count
        data += struct.pack('<H', self.partner_walk_count)

        # Padding2
        data += self.padding2

        # Illegal egg check
        data += bytes([self.illegal_egg_check_ver120])

        # Egg hatch count
        data += struct.pack('<I', self.egg_hatch_count)

        # Mega power and timer
        data += struct.pack('<f', self.mega_power)
        data += struct.pack('<f', self.mega_evo_timer)

        # Player HP
        data += struct.pack('<I', self.player_hp)

        # Birthday flags
        data += bytes([self.is_birthday_set, self.is_birthday_event_view])

        # Birthday event year
        data += struct.pack('<H', self.birthday_event_view_year)

        # Add final 2 bytes padding to reach 120 bytes
        data += bytes(2)

        return data

    def get_name_string(self):
        """Convert name array to a string (assuming UTF-16 encoding)"""
        # Convert StrCode array to bytes and decode as UTF-16
        name_bytes = b''.join(struct.pack('<H', code) for code in self.name if code != 0)
        try:
            # Try to decode as UTF-16, stopping at null terminator
            null_pos = name_bytes.find(b'\x00\x00')
            if null_pos != -1:
                name_bytes = name_bytes[:null_pos]
            return name_bytes.decode('utf-16-le')
        except:
            return f"Name codes: {self.name}"

    def set_name_string(self, name_str):
        """Set name from string (converts to UTF-16)"""
        # Encode to UTF-16 little endian
        encoded = name_str.encode('utf-16-le')
        # Pad to 26 bytes (13 uint16_t)
        padded = encoded.ljust(26, b'\x00')

        # Convert back to uint16 array
        self.name = []
        for i in range(0, 26, 2):
            if i + 1 < len(padded):
                code = struct.unpack('<H', padded[i:i + 2])[0]
                self.name.append(code)

        # Ensure we have exactly 13 elements
        while len(self.name) < 13:
            self.name.append(0)
        self.name = self.name[:13]

    def get_gender(self):
        """Get gender as enum"""
        return Gender(self.sex)

    def set_gender(self, gender):
        """Set gender from enum"""
        self.sex = gender.value

    def is_valid_nex_unique_id(self):
        """Check if NEX unique ID is valid"""
        return self.nex_unique_id != 0

    def is_valid_nex_principal_rom_id(self):
        """Check if NEX principal ROM ID is valid"""
        return self.nex_principal_rom_id != 0

    def is_valid_npln_user_id(self):
        """Check if NPLN user ID is valid"""
        return self.is_npln_user_id_valid != 0

    def get_id_low(self):
        """Get lower 16 bits of ID"""
        return self.id & 0xFFFF

    def get_draw_id(self):
        """Get display ID (last 6 digits)"""
        return self.id % 1000000

    def __str__(self):
        return (f"CoreData(ID={self.id}, Name='{self.get_name_string()}', "
                f"Gender={self.get_gender().name}, Rank={self.member_rank}, "
                f"RankExp={self.member_rank_exp}, Birthday={self.birthday_month}/{self.birthday_day})")


class UserDataSaveDataAccessor:
    def __init__(self):
        self.core_data = CoreData()

    @classmethod
    def from_bytes(cls, data):
        accessor = cls()
        accessor.core_data = CoreData.from_bytes(data)
        return accessor

    def to_bytes(self):
        return self.core_data.to_bytes()

    def get_id(self):
        return self.core_data.id

    def set_id(self, id):
        self.core_data.id = id

    def get_rom_code(self):
        return self.core_data.rom_code

    def get_sex(self):
        return self.core_data.sex

    def set_sex(self, sex):
        self.core_data.sex = sex

    def get_poke_language_id(self):
        return self.core_data.poke_language_id

    def set_poke_language_id(self, lang_id):
        self.core_data.poke_language_id = lang_id

    def get_nex_unique_id(self):
        return self.core_data.nex_unique_id

    def set_nex_unique_id(self, id):
        self.core_data.nex_unique_id = id

    def get_nex_principal_rom_id(self):
        return self.core_data.nex_principal_rom_id

    def set_nex_principal_rom_id(self, id):
        self.core_data.nex_principal_rom_id = id

    def get_player_icon_id(self):
        return self.core_data.player_icon_id

    def set_player_icon_id(self, id):
        self.core_data.player_icon_id = id

    def get_member_rank(self):
        return self.core_data.member_rank

    def set_member_rank(self, rank):
        self.core_data.member_rank = min(rank, 99)  # MEMBER_RANK_MAX = 99

    def get_member_rank_exp(self):
        return self.core_data.member_rank_exp

    def set_member_rank_exp(self, exp):
        self.core_data.member_rank_exp = min(exp, 99999)  # MEMBER_RANK_EXP_MAX = 99999

    def get_egg_hatch_count(self):
        return self.core_data.egg_hatch_count

    def set_egg_hatch_count(self, count):
        self.core_data.egg_hatch_count = count

    def get_birthday_month(self):
        return self.core_data.birthday_month

    def get_birthday_day(self):
        return self.core_data.birthday_day

    def set_birthday(self, month, day):
        self.core_data.birthday_month = month
        self.core_data.birthday_day = day
        self.core_data.is_birthday_set = 1

    def get_partner_walk_count(self):
        return self.core_data.partner_walk_count

    def update_partner_walk_count(self, count):
        self.core_data.partner_walk_count += count

    def reset_partner_walk_count(self):
        self.core_data.partner_walk_count = 0

    def get_mega_power(self):
        return self.core_data.mega_power

    def set_mega_power(self, value):
        self.core_data.mega_power = value

    def get_mega_evo_timer(self):
        return self.core_data.mega_evo_timer

    def set_mega_evo_timer(self, time):
        self.core_data.mega_evo_timer = time

    def get_player_hp(self):
        return self.core_data.player_hp

    def set_player_hp(self, value):
        self.core_data.player_hp = value

    def is_illegal_egg_check_ver120_finished(self):
        return self.core_data.illegal_egg_check_ver120 != 0

    def set_illegal_egg_check_ver120(self, flag):
        self.core_data.illegal_egg_check_ver120 = 1 if flag else 0

    def __str__(self):
        return str(self.core_data)