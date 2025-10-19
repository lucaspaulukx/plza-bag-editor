# PLZA Save Recovery Tool
<sub>This project is not associated with TPC (The Pokémon Company), GameFreak, Nintendo nor any other entity.</sub>

---

## What's this?

This is a tool used to repair corrupted save files for **Pokémon Legends Z-A**, written in Python.  
Currently, it focuses on **bag corruption**, but additional recovery methods for other inconsistencies are planned.

---

## 🧩 Dependencies

- **Python 3.13+** (earlier Python 3 versions should also work)

---

## 🚀 How to use

1. **Dump your save** using [JKSV](https://github.com/J-D-K/JKSV) or a similar save manager.  
2. **Copy your save file** (usually named `main`) to your PC.  
3. **Download the latest release ZIP** from the [Releases](https://github.com/azalea-w/plza-recovery/releases) section.  
4. **Extract** the ZIP file to a folder of your choice.  
5. **Open your terminal** (PowerShell or CMD on Windows, or any shell on Linux/macOS).  
6. **Run the script:**

   ```bash
   python main.py <path/to/save/main>
   ```

   Example:
   ```bash
   python main.py "C:\Users\YourName\Desktop\main"
   ```

7. Once running, you will see the **main menu**:

   ```
   ========= PLZA Bag Manager =========
   [1] List items
   [2] Add item
   [3] Remove item
   [4] Save and exit
   [5] Exit without saving
   ====================================
   ```

   - **List items** — Displays all current items in your bag, with their categories and quantities.  
   - **Add item** — Lets you pick a category, choose an item, and set a quantity to add.  
   - **Remove item** — Lets you pick a category and remove specific items from your bag.  
   - **Save and exit** — Saves your changes to a new file.  
   - **Exit without saving** — Quits the program without modifying anything.

8. After saving, a new file will be created with `_modified` appended to the original filename.  
   Example:
   ```
   main -> main_modified
   ```

9. Restore the modified save to your console using **JKSV** or another compatible save manager.

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
