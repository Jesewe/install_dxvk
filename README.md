# DXVK Installation Script

## Overview

This Python CLI script automates the installation of [DXVK](https://github.com/doitsujin/dxvk), a Vulkan-based translation layer for Direct3D 8, 9, 10, and 11, into a specified game directory. It downloads the specified or latest DXVK release from GitHub and copies the required DLLs to the appropriate location (`system32` or `syswow64` subdirectories if they exist, or the game directory itself). The script supports both interactive prompts and command-line arguments, making it versatile for running Windows games on Linux with Wine or DXVK Native setups. It also includes auto-detection of the required DXVK version based on game executable dependencies.

## Installation

### Prerequisites

- Python 3.9+
- Required Python libraries (listed in `requirements.txt`)

### Steps

1. **Clone or Download the Script**:

   - Clone this repository or download the `install_dxvk.py` and `requirements.txt` files.

2. **Install Dependencies**:

   - Install the required Python libraries:
     ```bash
     pip install -r requirements.txt
     ```

3. **Run the Script**:

   - **Interactive Mode**:
     Execute the script without arguments to use interactive prompts:

     ```bash
     python install_dxvk.py
     ```

     Follow the prompts to specify:

     - **Game Directory**: Enter the path to the game directory (e.g., `/home/user/games/MyGame`).
     - **Bitness**: Choose `x32` or `x64` based on the game's architecture.
     - **DXVK Version**: If not auto-detected, select the Direct3D version (1 for D3D8, 2 for D3D9, 3 for D3D10, 4 for D3D11).

   - **Command-Line Mode**:
     Run the script with arguments to skip prompts:
     ```bash
     python install_dxvk.py --game-dir /path/to/game --bitness x64 --dxvk-version d3d11 --dxvk-release v2.3
     ```
     Available arguments:
     - `--game-dir`: Path to the game directory (e.g., `/home/user/games/MyGame`).
     - `--bitness`: Game architecture (`x32` or `x64`).
     - `--dxvk-version`: DXVK version (`d3d8`, `d3d9`, `d3d10`, or `d3d11`). If omitted, the script attempts to auto-detect the version.
     - `--dxvk-release`: Specific DXVK release version (e.g., `v2.3`). If omitted, the latest release is used.

4. **Post-Installation**:
   - For **Wine**: Use `winecfg` to add native DLL overrides for the installed DLLs (e.g., `d3d9`, `d3d11`, `dxgi`).
   - For **DXVK Native**: Ensure the game loads DLLs from the installed location and set the `DXVK_WSI_DRIVER` environment variable (e.g., `export DXVK_WSI_DRIVER=SDL2`).
   - Verify DXVK usage by setting:
     ```bash
     export DXVK_HUD=1
     ```
     Then run the game to check if DXVK is active.

## Features

- **Flexible Input**: Supports both interactive prompts and command-line arguments for game directory, bitness, DXVK version, and specific release version.
- **Specific Version Installation**: Allows installation of a specific DXVK release (e.g., `v2.2`) using the `--dxvk-release` argument.
- **Auto-Detection of DXVK Version**: Automatically detects the required DXVK version (D3D8, D3D9, D3D10, or D3D11) by analyzing `.exe` files in the game directory using the `pefile` library.
- **Existing Version Detection**: Checks for existing DXVK installations by examining DLLs (`d3d8.dll`, `d3d9.dll`, `d3d10core.dll`, `d3d11.dll`, `dxgi.dll`) and prompts to overwrite if a different version is detected.
- **Automated Download**: Fetches the specified or latest DXVK release from [GitHub](https://github.com/doitsujin/dxvk/releases).
- **User-Friendly CLI**: Provides clear, colored output using `colorama` for interactive prompts and error messages.
- **Progress Bar**: Displays a download progress bar using `tqdm`.
- **Flexible Installation**: Copies DLLs to the game directory's `system32` (and `syswow64` for x64 if it exists) or directly to the game directory if no subdirectories are found.
- **Support for Wine and DXVK Native**: Works with both Wine-based setups and DXVK Native for game ports.
- **Fast JSON Parsing**: Uses `orjson` for efficient parsing of GitHub API responses.
- **Error Handling**: Provides clear error messages for invalid inputs, failed downloads, missing files, or invalid DXVK releases.

## Troubleshooting

- **No .exe files found**: If auto-detection fails because no `.exe` files are found, the script will prompt for manual DXVK version selection. Ensure the game directory contains the game's executable.
- **Invalid DXVK release**: If the specified `--dxvk-release` (e.g., `v2.3`) is not found on GitHub, check the available releases at [DXVK Releases](https://github.com/doitsujin/dxvk/releases).
- **Failed to analyze .exe files**: Ensure `pefile` is installed (`pip install pefile`) and that the `.exe` files are accessible and not corrupted.
- **DLLs not loaded by game**: Verify DLL overrides in `winecfg` for Wine or check the game's DLL loading path for DXVK Native.
- **Network errors**: Ensure a stable internet connection when downloading DXVK releases.

## License

This project is licensed under the [MIT License](LICENSE).
