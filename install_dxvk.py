import os
import requests
import tarfile
import shutil
import tempfile
import pathlib
from tqdm import tqdm
from colorama import init, Fore, Style
import orjson

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

def get_latest_dxvk_release():
    """Fetch the latest DXVK release URL and version."""
    print(f"{Fore.YELLOW}Fetching latest DXVK release...{Style.RESET_ALL}")
    api_url = "https://api.github.com/repos/doitsujin/dxvk/releases/latest"
    response = requests.get(api_url)
    response.raise_for_status()
    data = orjson.loads(response.content)
    for asset in data['assets']:
        if asset['name'].endswith('.tar.gz'):
            return asset['browser_download_url'], asset['name']
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

def check_existing_dxvk(target_dir, dlls, bitness, game_dir):
    """Check if DXVK DLLs already exist in the target directory."""
    existing_dlls = []
    for dll in dlls:
        if (target_dir / dll).exists():
            existing_dlls.append(dll)
    if bitness == 'x64' and (game_dir / 'syswow64').exists():
        syswow64_dir = game_dir / 'syswow64'
        for dll in dlls:
            if (syswow64_dir / dll).exists():
                existing_dlls.append(f"{dll} (syswow64)")
    if existing_dlls:
        print(f"{Fore.YELLOW}Existing DXVK DLLs found: {', '.join(existing_dlls)}{Style.RESET_ALL}")
        while True:
            choice = input(f"{Fore.GREEN}Do you want to reinstall DXVK? (yes/no): {Style.RESET_ALL}").strip().lower()
            if choice in ['yes', 'y']:
                return True
            elif choice in ['no', 'n']:
                print(f"{Fore.YELLOW}Installation cancelled by user.{Style.RESET_ALL}")
                input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                exit(0)
            print(f"{Fore.RED}Invalid input. Please enter 'yes' or 'no'.{Style.RESET_ALL}")
    return True

def main():
    print(f"{Fore.BLUE}DXVK Installation Script{Style.RESET_ALL}")
    
    # Prompt for game directory
    game_dir = pathlib.Path(prompt_game_directory())
    
    # Prompt for bitness
    bitness = prompt_bitness()
    
    # Prompt for DXVK version
    dxvk_version, dlls = prompt_dxvk_version()
    
    # Determine target directory (game directory or system32 subdirectory)
    target_dir = game_dir / 'system32' if (game_dir / 'system32').exists() else game_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Check for existing DXVK DLLs
    if not check_existing_dxvk(target_dir, dlls, bitness, game_dir):
        return
    
    # Fetch latest DXVK release
    try:
        download_url, release_name = get_latest_dxvk_release()
        print(f"{Fore.GREEN}Found release: {release_name}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Failed to fetch DXVK release: {e}{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
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
        
        print(f"{Fore.GREEN}DXVK {dxvk_version} ({bitness}) installed successfully to {target_dir}.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please ensure the game is configured to use these DLLs (e.g., via winecfg for Wine or game settings for DXVK Native).{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}You can verify DXVK usage by setting DXVK_HUD=1 environment variable.{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Installation complete. Press Enter to exit...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")