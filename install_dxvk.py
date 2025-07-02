import os
import requests
import tarfile
import shutil
import tempfile
import pathlib
from tqdm import tqdm
from colorama import init, Fore, Style
import orjson
import argparse
import pefile
import glob

# Initialize colorama for cross-platform colored output
init()

def download_file(url, dest_path):
    """Download a file with a progress bar."""
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 KB
    with open(dest_path, 'wb') as f, tqdm(
        desc=f"{Fore.CYAN}Downloading{Style.RESET_ALL}",
        total=total_size,
        unit='iB',
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        for data in response.iter_content(block_size):
            size = f.write(data)
            bar.update(size)

def get_dxvk_release(version=None):
    """Fetch the specified or latest DXVK release URL, name, and version."""
    print(f"{Fore.YELLOW}Fetching {'specified' if version else 'latest'} DXVK release...{Style.RESET_ALL}")
    api_url = f"https://api.github.com/repos/doitsujin/dxvk/releases{'/tags/' + version if version else '/latest'}"
    response = requests.get(api_url)
    response.raise_for_status()
    data = orjson.loads(response.content)
    version = data['tag_name'] if version else data['tag_name']
    for asset in data['assets'] if version else data['assets']:
        if asset['name'].endswith('.tar.gz'):
            return asset['browser_download_url'], asset['name'], version
    raise Exception("No .tar.gz release found")

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

def check_existing_dxvk(target_dir, dlls, bitness, game_dir, latest_version, selected_dxvk_version):
    """Check for existing DXVK DLLs and version, prompt for reinstall if different."""
    existing_version, existing_dlls = get_existing_dxvk_version(target_dir, game_dir, bitness)
    
    if existing_dlls:
        print(f"{Fore.YELLOW}Existing DXVK version ({existing_version}) found with DLLs: {', '.join(existing_dlls)}{Style.RESET_ALL}")
        if existing_version != selected_dxvk_version:
            print(f"{Fore.YELLOW}Selected DXVK version is {selected_dxvk_version} (release: {latest_version}).{Style.RESET_ALL}")
            while True:
                choice = input(f"{Fore.GREEN}Do you want to remove the existing {existing_version} version and install {selected_dxvk_version} ({latest_version})? (yes/no): {Style.RESET_ALL}").strip().lower()
                if choice in ['yes', 'y']:
                    # Remove existing DLLs
                    for dll in ['d3d8.dll', 'd3d9.dll', 'd3d10core.dll', 'd3d11.dll', 'dxgi.dll']:
                        dll_path = target_dir / dll
                        if dll_path.exists():
                            os.remove(dll_path)
                            print(f"{Fore.CYAN}Removed {dll_path}{Style.RESET_ALL}")
                        if bitness == 'x64' and (game_dir / 'syswow64').exists():
                            syswow64_dll = game_dir / 'syswow64' / dll
                            if syswow64_dll.exists():
                                os.remove(syswow64_dll)
                                print(f"{Fore.CYAN}Removed {syswow64_dll}{Style.RESET_ALL}")
                    return True
                elif choice in ['no', 'n']:
                    print(f"{Fore.YELLOW}Installation cancelled by user.{Style.RESET_ALL}")
                    input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                    exit(0)
                print(f"{Fore.RED}Invalid input. Please enter 'yes' or 'no'.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Current DXVK version ({existing_version}) matches the selected version.{Style.RESET_ALL}")
            while True:
                choice = input(f"{Fore.GREEN}Do you want to reinstall DXVK {existing_version} ({latest_version})? (yes/no): {Style.RESET_ALL}").strip().lower()
                if choice in ['yes', 'y']:
                    # Remove existing DLLs
                    for dll in ['d3d8.dll', 'd3d9.dll', 'd3d10core.dll', 'd3d11.dll', 'dxgi.dll']:
                        dll_path = target_dir / dll
                        if dll_path.exists():
                            os.remove(dll_path)
                            print(f"{Fore.CYAN}Removed {dll_path}{Style.RESET_ALL}")
                        if bitness == 'x64' and (game_dir / 'syswow64').exists():
                            syswow64_dll = game_dir / 'syswow64' / dll
                            if syswow64_dll.exists():
                                os.remove(syswow64_dll)
                                print(f"{Fore.CYAN}Removed {syswow64_dll}{Style.RESET_ALL}")
                    return True
                elif choice in ['no', 'n']:
                    print(f"{Fore.YELLOW}Installation cancelled by user.{Style.RESET_ALL}")
                    input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                    exit(0)
                print(f"{Fore.RED}Invalid input. Please enter 'yes' or 'no'.{Style.RESET_ALL}")
    return True

def main():
    parser = argparse.ArgumentParser(description="DXVK Installation Script")
    parser.add_argument('--game-dir', type=validate_directory, help="Path to the game directory")
    parser.add_argument('--bitness', type=validate_bitness, choices=['x32', 'x64'], help="Bitness (x32 or x64)")
    parser.add_argument('--dxvk-version', type=validate_dxvk_version, help="DXVK version (d3d8, d3d9, d3d10, d3d11)")
    parser.add_argument('--dxvk-release', type=validate_dxvk_release, help="Specific DXVK release version (e.g., v2.3 or v2.3.1)")
    
    args = parser.parse_args()

    print(f"{Fore.BLUE}DXVK Installation Script{Style.RESET_ALL}")
    
    # Use command-line arguments if provided, otherwise prompt
    game_dir = args.game_dir if args.game_dir else pathlib.Path(prompt_game_directory())
    bitness = args.bitness if args.bitness else prompt_bitness()
    
    # Auto-detect DXVK version if not provided
    if args.dxvk_version:
        dxvk_version, dlls = args.dxvk_version
    else:
        dxvk_version, dlls = detect_dxvk_version(game_dir)
        if not dxvk_version:
            dxvk_version, dlls = prompt_dxvk_version()
    
    # Fetch specified or latest DXVK release
    try:
        download_url, release_name, latest_version = get_dxvk_release(args.dxvk_release)
        print(f"{Fore.GREEN}Found release: {release_name} (version {latest_version}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Failed to fetch DXVK release: {e}{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
        return
    
    # Check for existing DXVK DLLs and version
    if not check_existing_dxvk(target_dir=game_dir / 'system32' if (game_dir / 'system32').exists() else game_dir,
                             dlls=dlls,
                             bitness=bitness,
                             game_dir=game_dir,
                             latest_version=latest_version,
                             selected_dxvk_version=dxvk_version):
        return
    
    # Create temporary directory
    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_path = os.path.join(tmp_dir, release_name)
        
        # Download the release
        try:
            download_file(download_url, tar_path)
        except Exception as e:
            print(f"{Fore.RED}Failed to download DXVK release: {e}{Style.RESET_ALL}")
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
            return
        
        # Extract the tar.gz
        print(f"{Fore.YELLOW}Extracting archive...{Style.RESET_ALL}")
        try:
            with tarfile.open(tar_path, 'r:gz') as tar:
                tar.extractall(tmp_dir, filter='data')  # Explicit filter for Python 3.14
        except Exception as e:
            print(f"{Fore.RED}Failed to extract archive: {e}{Style.RESET_ALL}")
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
            return
        
        # Find the extracted DXVK directory
        dxvk_dir = os.path.join(tmp_dir, release_name.replace('.tar.gz', ''))
        if not os.path.isdir(dxvk_dir):
            print(f"{Fore.RED}DXVK directory not found in extracted archive.{Style.RESET_ALL}")
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
            return
        
        # Determine target directory (game directory or system32 subdirectory)
        target_dir = game_dir / 'system32' if (game_dir / 'system32').exists() else game_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy DLLs based on bitness
        src_dir = os.path.join(dxvk_dir, bitness)
        for dll in dlls:
            src_path = os.path.join(src_dir, dll)
            dest_path = target_dir / dll
            if not os.path.isfile(src_path):
                print(f"{Fore.RED}DLL {dll} not found in {src_dir}.{Style.RESET_ALL}")
                input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                return
            shutil.copy(src_path, dest_path)
            print(f"{Fore.CYAN}Copied {dll} to {dest_path}{Style.RESET_ALL}")
        
        # For x64, also copy x32 DLLs to syswow64 if it exists
        if bitness == 'x64' and (game_dir / 'syswow64').exists():
            syswow64_dir = game_dir / 'syswow64'
            syswow64_dir.mkdir(parents=True, exist_ok=True)
            src_dir_x32 = os.path.join(dxvk_dir, 'x32')
            if not os.path.isdir(src_dir_x32):
                print(f"{Fore.RED}32-bit DLL directory not found in {dxvk_dir}.{Style.RESET_ALL}")
                input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                return
            for dll in dlls:
                src_path = os.path.join(src_dir_x32, dll)
                if not os.path.isfile(src_path):
                    print(f"{Fore.RED}DLL {dll} not found in {src_dir_x32}.{Style.RESET_ALL}")
                    input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                    return
                dest_path = syswow64_dir / dll
                shutil.copy(src_path, dest_path)
                print(f"{Fore.CYAN}Copied {dll} to {dest_path}{Style.RESET_ALL}")
        
        # Copy dxvk.conf if it exists in the archive
        dxvk_conf_src = os.path.join(dxvk_dir, 'dxvk.conf')
        if os.path.isfile(dxvk_conf_src):
            shutil.copy(dxvk_conf_src, target_dir / 'dxvk.conf')
            print(f"{Fore.CYAN}Copied dxvk.conf to {target_dir / 'dxvk.conf'}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}DXVK {dxvk_version} ({bitness}, release {latest_version}) installed successfully to {target_dir}.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please ensure the game is configured to use these DLLs (e.g., via winecfg for Wine or game settings for DXVK Native).{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}You can verify DXVK usage by setting DXVK_HUD=1 environment variable.{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Installation complete. Press Enter to exit...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")