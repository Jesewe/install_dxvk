## Summary

- **Pre-install Check:** The script now checks if DXVK DLLs already exist in the target directory. If they do, it prompts the user for confirmation before reinstalling, preventing accidental overwrites.
- **Error Handling:** Added `try...except` blocks for the download and extraction processes to gracefully handle network or file-related failures.
- **Versioning:** The PyInstaller build process now embeds version information from a `version.txt` file into the final executable, allowing users to easily identify the installer version.
