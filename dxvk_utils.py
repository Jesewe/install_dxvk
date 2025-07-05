import os
import pathlib
import argparse
import glob
import pefile
from colorama import Fore, Style

def prompt_game_directory():
    """Prompt the user for the game directory and validate it."""
    while True:
        game_dir = input(f"{Fore.GREEN}Enter the game directory path: {Style.RESET_ALL}").strip()
        if os.path.isdir(game_dir):
            return game_dir
        print(f"{Fore.RED}Invalid directory. Please enter a valid path.{Style.RESET_ALL}")

def prompt_bitness():
    """Prompt the user for the bitness (x32 or x64)."""
    while True:
        bitness = input(f"{Fore.GREEN}Select bitness (x32 or x64): {Style.RESET_ALL}").strip().lower()
        if bitness in ['x32', 'x64']:
            return bitness
        print(f"{Fore.RED}Invalid input. Please enter 'x32' or 'x64'.{Style.RESET_ALL}")

def prompt_dxvk_version():
    """Prompt the user for the DXVK version (D3D8, D3D9, D3D10, D3D11)."""
    while True:
        print(f"\n{Fore.YELLOW}Available DXVK versions:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. D3D8 (requires d3d8.dll, d3d9.dll){Style.RESET_ALL}")
        print(f"{Fore.CYAN}2. D3D9 (requires d3d9.dll){Style.RESET_ALL}")
        print(f"{Fore.CYAN}3. D3D10 (requires d3d10core.dll, d3d11.dll, dxgi.dll){Style.RESET_ALL}")
        print(f"{Fore.CYAN}4. D3D11 (requires d3d11.dll, dxgi.dll){Style.RESET_ALL}")
        choice = input(f"{Fore.GREEN}Select DXVK version (1-4): {Style.RESET_ALL}").strip()
        if choice == '1':
            return 'd3d8', ['d3d8.dll', 'd3d9.dll']
        elif choice == '2':
            return 'd3d9', ['d3d9.dll']
        elif choice == '3':
            return 'd3d10', ['d3d10core.dll', 'd3d11.dll', 'dxgi.dll']
        elif choice == '4':
            return 'd3d11', ['d3d11.dll', 'dxgi.dll']
        print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and 4.{Style.RESET_ALL}")

def detect_dxvk_version(game_dir):
    """Auto-detect the required DXVK version by analyzing .exe files in the game directory."""
    dll_to_dxvk = {
        'd3d8.dll': 'd3d8',
        'd3d9.dll': 'd3d9',
        'd3d10core.dll': 'd3d10',
        'd3d11.dll': 'd3d11',
        'dxgi.dll': 'd3d11'  # dxgi.dll is used by both d3d10 and d3d11, prioritize d3d11
    }
    dxvk_version_map = {
        'd3d8': ['d3d8.dll', 'd3d9.dll'],
        'd3d9': ['d3d9.dll'],
        'd3d10': ['d3d10core.dll', 'd3d11.dll', 'dxgi.dll'],
        'd3d11': ['d3d11.dll', 'dxgi.dll']
    }
    
    exe_files = glob.glob(os.path.join(game_dir, "*.exe"))
    if not exe_files:
        print(f"{Fore.YELLOW}No .exe files found in {game_dir}. Falling back to manual selection.{Style.RESET_ALL}")
        return None, None
    
    detected_dlls = set()
    for exe in exe_files:
        try:
            pe = pefile.PE(exe)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8').lower()
                if dll_name in dll_to_dxvk:
                    detected_dlls.add(dll_name)
            pe.close()
        except Exception as e:
            print(f"{Fore.YELLOW}Failed to analyze {exe}: {e}{Style.RESET_ALL}")
    
    if not detected_dlls:
        print(f"{Fore.YELLOW}No Direct3D DLLs detected in .exe files. Falling back to manual selection.{Style.RESET_ALL}")
        return None, None
    
    # Determine the highest DXVK version based on detected DLLs
    detected_version = None
    for dll in detected_dlls:
        version = dll_to_dxvk.get(dll)
        if version and (not detected_version or version > detected_version):
            detected_version = version
    
    if detected_version:
        print(f"{Fore.GREEN}Detected DXVK version: {detected_version} based on DLLs: {', '.join(detected_dlls)}{Style.RESET_ALL}")
        return detected_version, dxvk_version_map[detected_version]
    
    return None, None

def validate_dxvk_version(version):
    """Validate DXVK version from command-line argument."""
    version_map = {
        'd3d8': ('d3d8', ['d3d8.dll', 'd3d9.dll']),
        'd3d9': ('d3d9', ['d3d9.dll']),
        'd3d10': ('d3d10', ['d3d10core.dll', 'd3d11.dll', 'dxgi.dll']),
        'd3d11': ('d3d11', ['d3d11.dll', 'dxgi.dll'])
    }
    if version.lower() not in version_map:
        raise argparse.ArgumentTypeError("DXVK version must be one of: d3d8, d3d9, d3d10, d3d11")
    return version_map[version.lower()]

def validate_bitness(bitness):
    """Validate bitness from command-line argument."""
    if bitness.lower() not in ['x32', 'x64']:
        raise argparse.ArgumentTypeError("Bitness must be either x32 or x64")
    return bitness.lower()

def validate_directory(directory):
    """Validate game directory from command-line argument."""
    if not os.path.isdir(directory):
        raise argparse.ArgumentTypeError(f"Directory '{directory}' does not exist")
    return pathlib.Path(directory)

def validate_dxvk_release(release):
    """Validate DXVK release version."""
    if not release.startswith('v') or not all(c.isdigit() or c == '.' for c in release[1:]):
        raise argparse.ArgumentTypeError("DXVK release must be in the format 'vX.Y[.Z]' (e.g., v2.3 or v2.3.1)")
    return release

def get_existing_dxvk_version(target_dir, game_dir, bitness):
    """Infer existing DXVK version based on DLL files in the target directory."""
    dll_sets = {
        'd3d11': ['d3d11.dll', 'dxgi.dll'],
        'd3d10': ['d3d10core.dll', 'd3d11.dll', 'dxgi.dll'],
        'd3d9': ['d3d9.dll'],
        'd3d8': ['d3d8.dll', 'd3d9.dll']
    }
    existing_dlls = []

    # Check DLLs in system32 or game directory
    for dll in ['d3d8.dll', 'd3d9.dll', 'd3d10core.dll', 'd3d11.dll', 'dxgi.dll']:
        if (target_dir / dll).exists():
            existing_dlls.append(dll)

    # Check syswow64 for x64 bitness
    if bitness == 'x64' and (game_dir / 'syswow64').exists():
        syswow64_dir = game_dir / 'syswow64'
        for dll in ['d3d8.dll', 'd3d9.dll', 'd3d10core.dll', 'd3d11.dll', 'dxgi.dll']:
            if (syswow64_dir / dll).exists():
                existing_dlls.append(f"{dll} (syswow64)")

    # Determine version based on complete DLL sets, checking higher versions first
    existing_version = None
    for version, dll_list in dll_sets.items():
        # Check if all required DLLs for this version are present in either system32 or syswow64
        if all((target_dir / dll).exists() for dll in dll_list) or \
           (bitness == 'x64' and (game_dir / 'syswow64').exists() and \
            all((game_dir / 'syswow64' / dll).exists() for dll in dll_list)):
            existing_version = version
            break

    if existing_dlls and not existing_version:
        existing_version = "unknown (DLLs detected)"

    return existing_version, existing_dlls