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
from dxvk_utils import (
    prompt_game_directory, prompt_bitness, prompt_dxvk_version,
    detect_dxvk_version, validate_dxvk_version, validate_bitness,
    validate_directory, validate_dxvk_release, get_existing_dxvk_version
)

# Initialize colorama for cross-platform colored output
init()

class DXVKInstaller:
    def __init__(self, game_dir, bitness, dxvk_version, dlls, dxvk_release=None):
        self.game_dir = pathlib.Path(game_dir)
        self.bitness = bitness
        self.dxvk_version = dxvk_version
        self.dlls = dlls
        self.dxvk_release = dxvk_release
        self.target_dir = self.game_dir / 'system32' if (self.game_dir / 'system32').exists() else self.game_dir

    def download_file(self, url, dest_path):
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

    def fetch_release(self):
        """Fetch the specified or latest DXVK release URL, name, and version."""
        print(f"{Fore.YELLOW}Fetching {'specified' if self.dxvk_release else 'latest'} DXVK release...{Style.RESET_ALL}")
        api_url = f"https://api.github.com/repos/doitsujin/dxvk/releases{'/tags/' + self.dxvk_release if self.dxvk_release else '/latest'}"
        response = requests.get(api_url)
        response.raise_for_status()
        data = orjson.loads(response.content)
        version = data['tag_name']
        for asset in data['assets']:
            if asset['name'].endswith('.tar.gz'):
                return asset['browser_download_url'], asset['name'], version
        raise Exception("No .tar.gz release found")

    def check_existing(self, latest_version):
        """Check for existing DXVK DLLs and version, prompt for reinstall if different."""
        existing_version, existing_dlls = get_existing_dxvk_version(self.target_dir, self.game_dir, self.bitness)
        
        if existing_dlls:
            print(f"{Fore.YELLOW}Existing DXVK version ({existing_version}) found with DLLs: {', '.join(existing_dlls)}{Style.RESET_ALL}")
            if existing_version != self.dxvk_version:
                print(f"{Fore.YELLOW}Selected DXVK version is {self.dxvk_version} (release: {latest_version}).{Style.RESET_ALL}")
                while True:
                    choice = input(f"{Fore.GREEN}Do you want to remove the existing {existing_version} version and install {self.dxvk_version} ({latest_version})? (yes/no): {Style.RESET_ALL}").strip().lower()
                    if choice in ['yes', 'y']:
                        # Remove existing DLLs
                        for dll in ['d3d8.dll', 'd3d9.dll', 'd3d10core.dll', 'd3d11.dll', 'dxgi.dll']:
                            dll_path = self.target_dir / dll
                            if dll_path.exists():
                                os.remove(dll_path)
                                print(f"{Fore.CYAN}Removed {dll_path}{Style.RESET_ALL}")
                            if self.bitness == 'x64' and (self.game_dir / 'syswow64').exists():
                                syswow64_dll = self.game_dir / 'syswow64' / dll
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
                            dll_path = self.target_dir / dll
                            if dll_path.exists():
                                os.remove(dll_path)
                                print(f"{Fore.CYAN}Removed {dll_path}{Style.RESET_ALL}")
                            if self.bitness == 'x64' and (self.game_dir / 'syswow64').exists():
                                syswow64_dll = self.game_dir / 'syswow64' / dll
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

    def install(self):
        """Install DXVK by downloading, extracting, and copying DLLs."""
        try:
            download_url, release_name, latest_version = self.fetch_release()
            print(f"{Fore.GREEN}Found release: {release_name} (version {latest_version}){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Failed to fetch DXVK release: {e}{Style.RESET_ALL}")
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
            return

        if not self.check_existing(latest_version):
            return

        with tempfile.TemporaryDirectory() as tmp_dir:
            tar_path = os.path.join(tmp_dir, release_name)
            
            # Download the release
            try:
                self.download_file(download_url, tar_path)
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
            
            # Ensure target directory exists
            self.target_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy DLLs based on bitness
            src_dir = os.path.join(dxvk_dir, self.bitness)
            for dll in self.dlls:
                src_path = os.path.join(src_dir, dll)
                dest_path = self.target_dir / dll
                if not os.path.isfile(src_path):
                    print(f"{Fore.RED}DLL {dll} not found in {src_dir}.{Style.RESET_ALL}")
                    input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                    return
                shutil.copy(src_path, dest_path)
                print(f"{Fore.CYAN}Copied {dll} to {dest_path}{Style.RESET_ALL}")
            
            # For x64, also copy x32 DLLs to syswow64 if it exists
            if self.bitness == 'x64' and (self.game_dir / 'syswow64').exists():
                syswow64_dir = self.game_dir / 'syswow64'
                syswow64_dir.mkdir(parents=True, exist_ok=True)
                src_dir_x32 = os.path.join(dxvk_dir, 'x32')
                if not os.path.isdir(src_dir_x32):
                    print(f"{Fore.RED}32-bit DLL directory not found in {dxvk_dir}.{Style.RESET_ALL}")
                    input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                    return
                for dll in self.dlls:
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
                shutil.copy(dxvk_conf_src, self.target_dir / 'dxvk.conf')
                print(f"{Fore.CYAN}Copied dxvk.conf to {self.target_dir / 'dxvk.conf'}{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}DXVK {self.dxvk_version} ({self.bitness}, release {latest_version}) installed successfully to {self.target_dir}.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please ensure the game is configured to use these DLLs (e.g., via winecfg for Wine or game settings for DXVK Native).{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}You can verify DXVK usage by setting DXVK_HUD=1 environment variable.{Style.RESET_ALL}")
            input(f"{Fore.GREEN}Installation complete. Press Enter to exit...{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="DXVK Installation Script")
    parser.add_argument('--game-dir', type=validate_directory, help="Path to the game directory")
    parser.add_argument('--bitness', type=validate_bitness, choices=['x32', 'x64'], help="Bitness (x32 or x64)")
    parser.add_argument('--dxvk-version', type=validate_dxvk_version, help="DXVK version (d3d8, d3d9, d3d10, d3d11)")
    parser.add_argument('--dxvk-release', type=validate_dxvk_release, help="Specific DXVK release version (e.g., v2.3 or v2.3.1)")
    
    args = parser.parse_args()

    print(f"{Fore.YELLOW}Welcome to the DXVK Installation Script!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This script will help you install DXVK for your game.{Style.RESET_ALL}")
    
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
    
    # Create and run installer
    installer = DXVKInstaller(game_dir, bitness, dxvk_version, dlls, args.dxvk_release)
    installer.install()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")