import os
import sys
from lib.plaza.crypto import HashDB, SwishCrypto
from lib.plaza.types import BagSave, BagEntry, CategoryType
from lib.plaza.util.items import item_db

save_file_magic = bytes([0x17, 0x2D, 0xBB, 0x06, 0xEA])

def load_save(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    if not data.startswith(save_file_magic):
        print("Invalid PLZA save file.")
        sys.exit(1)
    blocks = SwishCrypto.decrypt(data)
    hash_db = HashDB(blocks)
    bag_save_index = 0x21C9BD44
    bag_save = hash_db[bag_save_index]
    parsed_bag_save = BagSave.from_bytes(bag_save.data)
    return hash_db, bag_save_index, parsed_bag_save


def save_changes(file_path, hash_db):
    out = SwishCrypto.encrypt(hash_db.blocks)
    output_path = file_path + "_modified"
    with open(output_path, "wb") as f:
        f.write(out)
    print(f"Modified save written to: {output_path}")


def list_items(bag_save):
    print("\nItems in bag:")
    for i, entry in enumerate(bag_save.entries):
        if entry.quantity > 0 and i in item_db:
            name = item_db[i]["english_ui_name"]
            category = item_db[i]["expected_category"].name
            print(f"[{i:04}] {name} ({category}, Qty: {entry.quantity})")
    print("")


def choose_category():
    print("\nAvailable categories:")
    categories = list(CategoryType)
    for idx, cat in enumerate(categories):
        print(f"[{idx}] {cat.name}")
    try:
        choice = int(input("Select category: "))
        if 0 <= choice < len(categories):
            return categories[choice]
    except ValueError:
        pass
    print("Invalid category.")
    return None


def add_item(bag_save):
    category = choose_category()
    if not category:
        return

    print(f"\nItems in category {category.name}:")
    available_items = [
        (i, v) for i, v in item_db.items()
        if v["expected_category"] == category
    ]
    for i, v in available_items:
        print(f"[{i:04}] {v['english_ui_name']}")

    try:
        index = int(input("Enter item ID: "))
        qty = int(input("Quantity: "))
    except ValueError:
        print("Invalid input.")
        return

    if index not in item_db:
        print("Invalid ID.")
        return

    entry = BagEntry.from_bytes(bag_save.entries[index].to_bytes())
    entry.quantity = qty
    entry.category = item_db[index]["expected_category"].value
    bag_save.set_entry(index, entry)
    print(f"Added {qty}x {item_db[index]['english_ui_name']} ({category.name})")


def remove_item(bag_save):
    category = choose_category()
    if not category:
        return

    print(f"\nItems from this category in bag:")
    found = False
    for i, entry in enumerate(bag_save.entries):
        if entry.quantity > 0 and i in item_db and item_db[i]["expected_category"] == category:
            print(f"[{i:04}] {item_db[i]['english_ui_name']} (x{entry.quantity})")
            found = True

    if not found:
        print("No items found in this category.")
        return

    try:
        index = int(input("Enter item ID to remove: "))
    except ValueError:
        print("Invalid input.")
        return

    if index not in item_db:
        print("Invalid ID.")
        return

    entry = BagEntry.from_bytes(bag_save.entries[index].to_bytes())
    entry.quantity = 0
    bag_save.set_entry(index, entry)
    print(f"Removed {item_db[index]['english_ui_name']} from bag.")


def main_menu():
    print("""
========= PLZA Bag Manager =========
[1] List items
[2] Add item
[3] Remove item
[4] Save and exit
[5] Exit without saving
====================================
""")


if __name__ == "__main__":
    if not sys.argv[1:]:
        print("Usage: python main.py <path_to_save>")
        sys.exit(1)

    file_path = sys.argv[1]
    print(f"File: {file_path}")

    if not os.path.exists(file_path):
        print("File not found.")
        sys.exit(1)

    hash_db, bag_save_index, bag_save = load_save(file_path)

    while True:
        main_menu()
        choice = input("Choice: ").strip()

        if choice == "1":
            list_items(bag_save)
        elif choice == "2":
            add_item(bag_save)
        elif choice == "3":
            remove_item(bag_save)
        elif choice == "4":
            hash_db[bag_save_index].change_data(bag_save.to_bytes())
            save_changes(file_path, hash_db)
            break
        elif choice == "5":
            print("Exiting without saving changes.")
            break
        else:
            print("Invalid option.")
