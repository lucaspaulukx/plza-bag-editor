import os
import sys
from lib.plaza.crypto import HashDB, SwishCrypto
from lib.plaza.types.coredata import CoreData, Gender

CORE_DATA_INDEX = 148  # Confirmed based on save analysis

def load_coredata(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    blocks = SwishCrypto.decrypt(data)
    hash_db = HashDB(blocks)
    block = hash_db.blocks[CORE_DATA_INDEX]
    core_data = CoreData.from_bytes(block.data)
    return core_data, hash_db

def save_coredata(file_path, hash_db, core_data):
    hash_db.blocks[CORE_DATA_INDEX].change_data(core_data.to_bytes())
    output = SwishCrypto.encrypt(hash_db.blocks)
    output_path = f"{file_path}_character_edited"
    with open(output_path, "wb") as f:
        f.write(output)
    print(f"File saved as: {output_path}")

def show_info(core):
    print("\nCharacter Information:")
    print(f"ID: {core.id}")
    print(f"Name: {core.get_name_string()}")
    print(f"Gender: {core.get_gender().name}")
    print(f"Rank: {core.member_rank}")
    print(f"Experience: {core.member_rank_exp}")
    print(f"HP: {core.player_hp}")
    print(f"Birthday: {core.birthday_day}/{core.birthday_month}")
    print(f"Mega Power: {core.mega_power:.2f}")
    print(f"Egg Hatch Count: {core.egg_hatch_count}")

def edit_name(core):
    new_name = input("New name: ").strip()
    core.set_name_string(new_name)
    print("Name updated successfully.")

def edit_gender(core):
    print("1 - Male")
    print("2 - Female")
    choice = input("Select gender (1 or 2): ").strip()
    if choice == "1":
        core.set_gender(Gender.MALE)
    elif choice == "2":
        core.set_gender(Gender.FEMALE)
    else:
        print("Invalid option.")
        return
    print("Gender updated successfully.")

def edit_rank(core):
    rank = int(input("New rank (0-255): "))
    exp = int(input("New rank experience: "))
    core.member_rank = rank
    core.member_rank_exp = exp
    print("Rank updated successfully.")

def edit_hp(core):
    hp = int(input("New HP value: "))
    core.player_hp = hp
    print("HP updated successfully.")

def edit_birthday(core):
    day = int(input("Birthday day: "))
    month = int(input("Birthday month: "))
    core.birthday_day = day
    core.birthday_month = month
    core.is_birthday_set = 1
    print("Birthday updated successfully.")

def main_menu():
    print("""
CHARACTER MENU
1 - Show information
2 - Edit name
3 - Edit gender
4 - Edit rank
5 - Edit HP
6 - Edit birthday
7 - Save changes and exit
0 - Exit without saving
""")

if __name__ == "__main__":
    if not sys.argv[1:]:
        print("Usage: python character.py <save_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)

    core, hash_db = load_coredata(file_path)

    while True:
        main_menu()
        option = input("Select an option: ").strip()

        if option == "1":
            show_info(core)
        elif option == "2":
            edit_name(core)
        elif option == "3":
            edit_gender(core)
        elif option == "4":
            edit_rank(core)
        elif option == "5":
            edit_hp(core)
        elif option == "6":
            edit_birthday(core)
        elif option == "7":
            save_coredata(file_path, hash_db, core)
            break
        elif option == "0":
            print("Exiting without saving.")
            break
        else:
            print("Invalid option.")
