from .swishcrypto import SCBlock
from .fnvhash import FnvHash
from ..types.accessors import HashDBKeys

class HashDB:
    def __init__(self, blocks: list[SCBlock]):
        self.db: dict[str, SCBlock] = {}
        self.blocks = blocks

        for block in blocks:
            self.db[f"{block.key:08X}"] = block

    def __getitem__(self, item: str | int | HashDBKeys):
        if isinstance(item, int):
            item = f"{item:08X}"
        elif isinstance(item, HashDBKeys):
            item = f'{item.value:08X}'
        elif isinstance(item, str):
            item = f'{FnvHash.hash_fnv1a_32(item):08X}'
        else:
            raise TypeError()

        if not item in self.db:
            raise KeyError()

        return self.db[item]

    def __contains__(self, item: str):
        return item in self.db

    def __iter__(self):
        return iter(self.db)

    def __len__(self):
        return len(self.db)

    def __str__(self):
        return str(self.db)

    def __repr__(self):
        return repr(self.db)

    def __eq__(self, other):
        if isinstance(other, HashDB):
            return self.db == other.db
        return False

    def __setitem__(self, key: str | int, value: int):
        if isinstance(key, int):
            key = f"{key:08X}"
        elif isinstance(key, HashDBKeys):
            key = f'{key.value:08X}'
        elif isinstance(key, str):
            key = f'{FnvHash.hash_fnv1a_32(key):08X}'

        self.db[key].set_value(value)

