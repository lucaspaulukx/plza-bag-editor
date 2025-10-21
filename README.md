# PLZA Save Edit and Recovery Tool
<sub>This project is not associated with TPC (The Pokémon Company), GameFreak, Nintendo nor any other entity.</sub>

---

## What's this?

This is a tool used to repair corrupted save files for **Pokémon Legends Z-A**, written in Python.  
It can **automatically repair bag corruption** or **manually edit items** through an interactive interface.

---

## 🧩 Dependencies

- **Python 3.13+** (earlier Python 3 versions should also work)

---

## 🚀 How to use

### 1. Automatic Repair Mode (`main.py`)

Run this to automatically repair corrupted bag data and generate a fixed save file.

```bash
python main.py <path/to/save/main>
```

Example:
```bash
python main.py "C:\Users\YourName\Desktop\main"
```

After the process finishes, a new file will be created with `_modified` appended to the name:

```
main -> main_modified
```

You can then restore this file to your console using **JKSV** or another save manager.

---

### 2. Interactive Editor Mode (`terminal.py`)

Run this to manually inspect or modify items in your bag.

```bash
python terminal.py <path/to/save/main>
```

You will see the following menu:

```
========= PLZA Bag Manager =========
[1] List items
[2] Add item
[3] Remove item
[4] Save and exit
[5] Exit without saving
====================================
```

- **List items** — Displays all current items in your bag with category and quantity.  
- **Add item** — Lets you pick a category and add a specific item.  
- **Remove item** — Removes items by category or ID.  
- **Save and exit** — Writes your modifications to a new save file.  
- **Exit without saving** — Closes without changing your save.

---

## 💡 Example output

```bash
File: C:\Users\YourName\Desktop\main
Modified save written to: C:\Users\YourName\Desktop\main_modified
```

---

## 🧠 Thanks to

- The maintainers of [PKHeX](https://github.com/kwsch/PKHeX/) for implementing **SwishCrypto**.  
- **GameFreak** for creating the game.

---

