# DXVK Installation Script

## Overview

This Python CLI script automates the installation of [DXVK](https://github.com/doitsujin/dxvk), a Vulkan-based translation layer for Direct3D 8, 9, 10, and 11, into a specified game directory. It downloads the latest DXVK release from GitHub, prompts the user for the game directory, bitness (x32 or x64), and Direct3D version, and copies the required DLLs to the appropriate location (`system32` or `syswow64` subdirectories if they exist, or the game directory itself). The script supports both Wine and DXVK Native setups, making it versatile for running Windows games on Linux.

## Installation

### Prerequisites

- Python 3.9+
- Required Python libraries (listed in `requirements.txt`)

### Steps

1. **Clone or Download the Script**:

   - Clone this repository or download the `install_dxvk.py` and `requirements.txt` files.

2. **Install Dependencies**:

   - Install the required Python libraries using:
     ```bash
     pip install -r requirements.txt
     ```

3. **Run the Script**:

   - Execute the script with:
     ```bash
     python install_dxvk.py
     ```

4. **Follow Prompts**:

   - **Game Directory**: Enter the path to the game directory (e.g., `/home/user/games/MyGame`).
   - **Bitness**: Choose `x32` or `x64` based on the game's architecture.
   - **DXVK Version**: Select the Direct3D version (1 for D3D8, 2 for D3D9, 3 for D3D10, 4 for D3D11).

5. **Post-Installation**:
   - For **Wine**: Use `winecfg` to add native DLL overrides for the installed DLLs (e.g., `d3d9`, `d3d11`, `dxgi`).
   - For **DXVK Native**: Ensure the game loads DLLs from the installed location and set the `DXVK_WSI_DRIVER` environment variable (e.g., `export DXVK_WSI_DRIVER=SDL2`).
   - Verify DXVK usage by setting:
     ```bash
     export DXVK_HUD=1
     ```
     Then run the game to check if DXVK is active.

## Features

- **Automated Download**: Fetches the latest DXVK release from [GitHub](https://github.com/doitsujin/dxvk/releases/latest).
- **User-Friendly CLI**: Prompts for game directory, bitness (x32 or x64), and DXVK version (D3D8, D3D9, D3D10, or D3D11) with clear, colored output using `colorama`.
- **Progress Bar**: Displays a download progress bar using `tqdm`.
- **Flexible Installation**: Copies DLLs to the game directory's `system32` (and `syswow64` for x64 if it exists) or directly to the game directory if no subdirectories are found.
- **Support for Wine and DXVK Native**: Works with both Wine-based setups and DXVK Native for game ports.
- **Fast JSON Parsing**: Uses `orjson` for efficient parsing of GitHub API responses.
- **Error Handling**: Provides clear error messages for invalid inputs, failed downloads, or missing files.

## License

This project is licensed under the [MIT License](LICENSE).
