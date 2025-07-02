## Summary

- Infers the currently installed DXVK version **(d3d8, d3d9, etc.)** by checking for specific sets of DLLs in the target directories.
- Compares the detected version with the version selected for installation.
- If a different version is found, it provides an informative prompt asking the user if they want to replace it.
- The script now automatically detects the required **DXVK** version **(d3d8, d3d9, d3d10, or d3d11)** by analyzing the import tables of `.exe` files in the game directory.
- A new `--dxvk-release` command-line argument allows specifying a particular DXVK release tag for download.
