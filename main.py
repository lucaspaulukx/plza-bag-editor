import json
import os
import sys

from lib.plaza.crypto import HashDB, SwishCrypto
from lib.plaza.types import BagEntry, BagSave, CategoryType
from lib.plaza.util.items import item_db

save_file_magic = bytes([
	0x17, 0x2D, 0xBB, 0x06, 0xEA
])

if __name__ == "__main__":
    output_normally = True
    # noinspection DuplicatedCode
    if not sys.argv[1:]:
        print("Usage: python main.py <path_to_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_normally = False

    def log(message: str, _data = None):
        if not _data:
            _data = {}

        if output_normally: return print(message)
        elif not output_normally and _data: return print(json.dumps(_data | {"log": message}, indent=4))

    log(f"PLZA Save Repair Script")
    log(f"File path: {file_path}")

    if not os.path.exists(file_path):
        log(f"File not found: {file_path}", {"success": False})
        sys.exit(1)

    with open(file_path, "rb") as f:
        data = f.read()

    if not data.startswith(save_file_magic):
        log("File is not a PLZA save file", {"success": False})
        sys.exit(1)

    try:
        blocks = SwishCrypto.decrypt(data)
    except Exception as e:
        log(f"Error decrypting save file: {e}", {"success": False})
        sys.exit(1)

    log(f"Decrypted {len(blocks)} Blocks.")
    log(f"{SwishCrypto.get_is_hash_valid(data)=}")
    hash_db = HashDB(blocks)
    try:
        bag_save_index = 0x21C9BD44
        bag_save = hash_db[bag_save_index]
    except KeyError as e:
        log("BagSave index not found", {"success": False})
        sys.exit(1)

    if len(bag_save.data) != 48128:
        log("Invalid bag size, can't fix!", {"success": False})
        sys.exit(1)

    parsed_bag_save = BagSave.from_bytes(bag_save.data)

    log(f"Parsed BagSave: {parsed_bag_save}")

    log(parsed_bag_save)

    edited_count = 0
    for i, entry in enumerate(parsed_bag_save.entries):
        if not entry.quantity: continue

        # * Category < 0 causes crash
        if entry.category.value < 0:
            log(f"Item with corrupt category encountered")
            if i in item_db and not item_db[i]["canonical_name"].endswith("NAITO"):
                log(f"Restored {item_db[i]['english_ui_name']}")
                entry.category = item_db[i]["expected_category"].value
            else:
                entry.quantity = 0
            parsed_bag_save.set_entry(i, BagEntry.from_bytes(entry.to_bytes()))
            edited_count += 1

        # * Item is not used
        if not i in item_db:
            log(f"Removing item at index {i}")
            entry.quantity = 0
            entry.category = 0
            parsed_bag_save.set_entry(i, BagEntry.from_bytes(entry.to_bytes()))
            edited_count += 1
            continue

        # * Item has wrong category
        if entry.category != item_db[i]["expected_category"]:
            log(f"Editing category of {item_db[i]['english_ui_name']} ({entry.category} -> {item_db[i]['expected_category']})")
            entry.category = item_db[i]["expected_category"].value
            parsed_bag_save.set_entry(i, BagEntry.from_bytes(entry.to_bytes()))
            edited_count += 1

        # * Mega Stone Quantity Check
        if (
            entry.category == CategoryType.OTHER
            and item_db[i]["canonical_name"].strip("xy").endswith("NAITO")
            and entry.quantity > 1
        ):
            log(f"Editing quantity of {item_db[i]['english_ui_name']}")
            entry.quantity = 1
            parsed_bag_save.set_entry(i, BagEntry.from_bytes(entry.to_bytes()))
            edited_count += 1

    if not edited_count:
        log("No items needed to be modified!", {"success": True})
        sys.exit(0)

    log(f"Done! Modified {edited_count} entries", {"edited_count": edited_count, "success": True})

    hash_db[bag_save_index].change_data(parsed_bag_save.to_bytes())

    out = SwishCrypto.encrypt(hash_db.blocks)
    log(f"Writing Modified file to {file_path}_modified")

    with open(file_path + "_modified", "wb") as f:
        f.write(out)

    log(f"Wrote File, Exiting")
