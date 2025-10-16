import os
import sys

from lib.plaza.crypto import HashDB, SwishCrypto
from lib.plaza.types import BagSave, BagEntry, CategoryType
from lib.plaza.util.items import item_db


save_file_magic = bytes([
	0x17, 0x2D, 0xBB, 0x06, 0xEA
])


if __name__ == "__main__":
    # noinspection DuplicatedCode
    if not sys.argv[1:]:
        print("Usage: python main.py <path_to_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    print(F"PLZA Save Repair Script")
    print(f"File path: {file_path}")

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)

    with open(file_path, "rb") as f:
        data = f.read()

    if not data.startswith(save_file_magic):
        print("File is not a PLZA save file")
        sys.exit(1)

    try:
        blocks = SwishCrypto.decrypt(data)
    except Exception as e:
        print(f"Error decrypting save file: {e}")
        sys.exit(1)

    print(f"Decrypted {len(blocks)} Blocks.")
    print(f"{SwishCrypto.get_is_hash_valid(data)=}")
    hash_db = HashDB(blocks)
    try:
        bag_save_index = 0x21C9BD44
        bag_save = hash_db[bag_save_index]
    except KeyError as e:
        print("BagSave index not found")
        sys.exit(1)

    if len(bag_save.data) != 48128:
        print("Invalid bag size, can't fix!")
        sys.exit(1)

    parsed_bag_save = BagSave.from_bytes(bag_save.data)

    print(f"Parsed BagSave: {parsed_bag_save}")

    print(parsed_bag_save)

    edited_count = 0
    for i, entry in enumerate(parsed_bag_save.entries):
        if not entry.quantity: continue

        # * Category < 0 causes crash
        if entry.category.value < 0:
            print(f"Item with corrupt category encountered")
            if i in item_db and not item_db[i]["canonical_name"].endswith("NAITO"):
                print(f"Restored {item_db[i]['english_ui_name']}")
                entry.category = item_db[i]["expected_category"].value
            else:
                entry.quantity = 0
            parsed_bag_save.set_entry(i, BagEntry.from_bytes(entry.to_bytes()))
            edited_count += 1
            continue

        # * Item is not used
        if not i in item_db:
            print(f"Removing item at index {i}")
            entry.quantity = 0
            parsed_bag_save.set_entry(i, BagEntry.from_bytes(entry.to_bytes()))
            edited_count += 1
            continue

        # * Item has wrong category
        if entry.category != item_db[i]["expected_category"]:
            print(f"Editing category of {item_db[i]['english_ui_name']} ({entry.category} -> {item_db[i]['expected_category']})")
            entry.category = item_db[i]["expected_category"].value
            parsed_bag_save.set_entry(i, BagEntry.from_bytes(entry.to_bytes()))
            edited_count += 1
            continue

        # * Mega Stone Quantity Check
        if (
            entry.category == CategoryType.OTHER
            and item_db[i]["canonical_name"].strip("xy").endswith("NAITO")
            and entry.quantity > 1
        ):
            print(f"Editing quantity of {item_db[i]['english_ui_name']}")
            entry.quantity = 1
            parsed_bag_save.set_entry(i, BagEntry.from_bytes(entry.to_bytes()))
            edited_count += 1
            continue

    if not edited_count:
        print("No items needed to be modified!")
        sys.exit(0)

    print(f"Done! Modified {edited_count} entries")

    hash_db[bag_save_index].change_data(parsed_bag_save.to_bytes())

    out = SwishCrypto.encrypt(hash_db.blocks)
    print(f"Writing Modified file to {file_path}_modified")

    with open(file_path + "_modified", "wb") as f:
        f.write(out)

    print(f"Wrote File, Exiting")
