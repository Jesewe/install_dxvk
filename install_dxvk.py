import os
import requests
import tarfile
import shutil
import tempfile
import pathlib
import webbrowser
from tqdm import tqdm
from colorama import init, Fore, Style
import orjson
import argparse
from dxvk_utils import (
    prompt_game_directory, prompt_bitness, prompt_dxvk_version,
    detect_dxvk_version, validate_dxvk_version, validate_bitness,
    validate_directory, validate_dxvk_release, get_existing_dxvk_version,
    compare_versions, check_for_update, DXVK_VERSION_MAP,
)

# Initialize colorama for cross-platform colored output
init()

# Current script version
SCRIPT_VERSION = "v1.0.5"

_HTTP_TIMEOUT = (5, 30)  # (connect timeout, read timeout) in seconds

class InstallationCancelled(Exception):
    """Raised when the user explicitly cancels the installation flow.
    Handled by main() so that class methods never call exit() directly.
    """

class DXVKInstaller:
    def __init__(self, game_dir, bitness, dxvk_version, dlls, dxvk_release=None, session=None):
        self.game_dir     = pathlib.Path(game_dir)
        self.bitness      = bitness
        self.dxvk_version = dxvk_version
        self.dlls         = dlls
        self.dxvk_release = dxvk_release
        self.session      = session or requests.Session()
        self.target_dir   = (
            self.game_dir / 'system32'
            if (self.game_dir / 'system32').exists()
            else self.game_dir
        )

    def _prompt_user_yes_no(self, message):
        """Prompts the user with a yes/no question and returns a boolean."""
        while True:
            choice = input(f"{Fore.GREEN}{message} (yes/no): {Style.RESET_ALL}").strip().lower()
            if choice in ('yes', 'y'):
                return True
            if choice in ('no', 'n'):
                return False
            print(f"{Fore.RED}Invalid input. Please enter 'yes' or 'no'.{Style.RESET_ALL}")

    def download_file(self, url, dest_path):
        """Download a file with a progress bar."""
        response = self.session.get(url, stream=True, timeout=_HTTP_TIMEOUT)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024  # 1 KB
        with open(dest_path, 'wb') as f, tqdm(
            desc=f"{Fore.CYAN}Downloading{Style.RESET_ALL}",
            total=total_size,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
        ) as bar:
            for chunk in response.iter_content(block_size):
                size = f.write(chunk)
                bar.update(size)

    def fetch_release(self):
        """Fetch the specified or latest DXVK release URL, name, and version."""
        print(
            f"{Fore.YELLOW}Fetching "
            f"{'specified' if self.dxvk_release else 'latest'} DXVK release...{Style.RESET_ALL}"
        )
        suffix  = f"/tags/{self.dxvk_release}" if self.dxvk_release else "/latest"
        api_url = f"https://api.github.com/repos/doitsujin/dxvk/releases{suffix}"
        response = self.session.get(api_url, timeout=_HTTP_TIMEOUT)
        response.raise_for_status()
        data    = orjson.loads(response.content)
        version = data['tag_name']
        for asset in data['assets']:
            if asset['name'].endswith('.tar.gz'):
                return asset['browser_download_url'], asset['name'], version
        raise RuntimeError("No .tar.gz asset found in the DXVK release.")

    def _remove_existing_dlls(self):
        """Remove existing DXVK DLLs from the target and syswow64 directories."""
        all_dlls = list(dict.fromkeys(
            dll for dlls in DXVK_VERSION_MAP.values() for dll in dlls
        ))
        for dll in all_dlls:
            dll_path = self.target_dir / dll
            if dll_path.exists():
                os.remove(dll_path)
                print(f"{Fore.CYAN}Removed {dll_path}{Style.RESET_ALL}")
            if self.bitness == 'x64' and (self.game_dir / 'syswow64').exists():
                syswow64_dll = self.game_dir / 'syswow64' / dll
                if syswow64_dll.exists():
                    os.remove(syswow64_dll)
                    print(f"{Fore.CYAN}Removed {syswow64_dll}{Style.RESET_ALL}")

    def check_existing(self, latest_version):
        """Check for existing DXVK DLLs and prompt for reinstall if needed.

        Raises:
            InstallationCancelled: if the user declines to proceed.
        """
        existing_version, existing_dlls = get_existing_dxvk_version(
            self.target_dir, self.game_dir, self.bitness
        )

        if not existing_dlls:
            return

        print(
            f"{Fore.YELLOW}Existing DXVK version ({existing_version}) found "
            f"with DLLs: {', '.join(existing_dlls)}{Style.RESET_ALL}"
        )

        if existing_version != self.dxvk_version:
            print(
                f"{Fore.YELLOW}Selected DXVK version is "
                f"{self.dxvk_version} (release: {latest_version}).{Style.RESET_ALL}"
            )
            question = (
                f"Do you want to remove the existing {existing_version} version "
                f"and install {self.dxvk_version} ({latest_version})?"
            )
        else:
            print(
                f"{Fore.YELLOW}Current DXVK version ({existing_version}) "
                f"matches the selected version.{Style.RESET_ALL}"
            )
            question = f"Do you want to reinstall DXVK {existing_version} ({latest_version})?"

        if self._prompt_user_yes_no(question):
            self._remove_existing_dlls()
        else:
            raise InstallationCancelled("User declined to overwrite existing installation.")

    def _download_and_extract_release(self, download_url, release_name, tmp_dir):
        """Download and extract the DXVK release tarball.

        Returns the path to the extracted directory, or None on failure.
        """
        tar_path = os.path.join(tmp_dir, release_name)

        try:
            self.download_file(download_url, tar_path)
        except Exception as e:
            print(f"{Fore.RED}Failed to download DXVK release: {e}{Style.RESET_ALL}")
            return None

        print(f"{Fore.YELLOW}Extracting archive...{Style.RESET_ALL}")
        try:
            with tarfile.open(tar_path, 'r:gz') as tar:
                tar.extractall(tmp_dir, filter='data')
        except Exception as e:
            print(f"{Fore.RED}Failed to extract archive: {e}{Style.RESET_ALL}")
            return None

        dxvk_dir = os.path.join(tmp_dir, release_name.replace('.tar.gz', ''))
        if not os.path.isdir(dxvk_dir):
            print(f"{Fore.RED}DXVK directory not found in extracted archive.{Style.RESET_ALL}")
            return None

        return dxvk_dir

    def _copy_files(self, dxvk_dir):
        """Copy the necessary DLLs and config file to the target directory.

        Returns True on success, False on any missing file.
        """
        self.target_dir.mkdir(parents=True, exist_ok=True)

        src_dir = os.path.join(dxvk_dir, self.bitness)
        for dll in self.dlls:
            src_path = os.path.join(src_dir, dll)
            if not os.path.isfile(src_path):
                print(f"{Fore.RED}DLL {dll} not found in {src_dir}.{Style.RESET_ALL}")
                return False
            shutil.copy(src_path, self.target_dir / dll)
            print(f"{Fore.CYAN}Copied {dll} to {self.target_dir / dll}{Style.RESET_ALL}")

        if self.bitness == 'x64' and (self.game_dir / 'syswow64').exists():
            syswow64_dir  = self.game_dir / 'syswow64'
            syswow64_dir.mkdir(parents=True, exist_ok=True)
            src_dir_x32   = os.path.join(dxvk_dir, 'x32')
            if not os.path.isdir(src_dir_x32):
                print(f"{Fore.RED}32-bit DLL directory not found in {dxvk_dir}.{Style.RESET_ALL}")
                return False
            for dll in self.dlls:
                src_path = os.path.join(src_dir_x32, dll)
                if not os.path.isfile(src_path):
                    print(f"{Fore.RED}DLL {dll} not found in {src_dir_x32}.{Style.RESET_ALL}")
                    return False
                shutil.copy(src_path, syswow64_dir / dll)
                print(f"{Fore.CYAN}Copied {dll} to {syswow64_dir / dll}{Style.RESET_ALL}")

        dxvk_conf_src = os.path.join(dxvk_dir, 'dxvk.conf')
        if os.path.isfile(dxvk_conf_src):
            shutil.copy(dxvk_conf_src, self.target_dir / 'dxvk.conf')
            print(f"{Fore.CYAN}Copied dxvk.conf to {self.target_dir / 'dxvk.conf'}{Style.RESET_ALL}")

        return True

    def install(self):
        """Install DXVK by downloading, extracting, and copying DLLs.

        Raises:
            InstallationCancelled: propagated from check_existing().
        """
        try:
            download_url, release_name, latest_version = self.fetch_release()
            print(f"{Fore.GREEN}Found release: {release_name} (version {latest_version}){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Failed to fetch DXVK release: {e}{Style.RESET_ALL}")
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
            return

        self.check_existing(latest_version)

        with tempfile.TemporaryDirectory() as tmp_dir:
            dxvk_dir = self._download_and_extract_release(download_url, release_name, tmp_dir)
            if not dxvk_dir:
                input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                return

            if not self._copy_files(dxvk_dir):
                input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
                return

            print(
                f"{Fore.GREEN}DXVK {self.dxvk_version} ({self.bitness}, release {latest_version}) "
                f"installed successfully to {self.target_dir}.{Style.RESET_ALL}"
            )
            print(
                f"{Fore.YELLOW}Please ensure the game is configured to use these DLLs "
                f"(e.g., via winecfg for Wine or game settings for DXVK Native).{Style.RESET_ALL}"
            )
            print(
                f"{Fore.YELLOW}You can verify DXVK usage by setting the "
                f"DXVK_HUD=1 environment variable.{Style.RESET_ALL}"
            )
            input(f"{Fore.GREEN}Installation complete. Press Enter to exit...{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="DXVK Installation Script")
    parser.add_argument('--game-dir',     type=validate_directory,    help="Path to the game directory")
    parser.add_argument('--bitness',      type=validate_bitness,      choices=['x32', 'x64'], help="Bitness (x32 or x64)")
    parser.add_argument('--dxvk-version', type=validate_dxvk_version, help="DXVK version (d3d8, d3d9, d3d10, d3d11)")
    parser.add_argument('--dxvk-release', type=validate_dxvk_release, help="Specific DXVK release version (e.g. v2.3 or v2.3.1)")
    parser.add_argument('--check-update',    action='store_true', help="Check for script updates")
    parser.add_argument('--no-update-check', action='store_true', help="Skip checking for script updates")

    args = parser.parse_args()

    # Single shared session for all HTTP calls in this process.
    session = requests.Session()
    session.headers.update({'User-Agent': f'DXVK-Installer/{SCRIPT_VERSION}'})

    # A DXVKInstaller instance is no longer needed just to run an update check.
    run_update_check = args.check_update or (
        not args.no_update_check
        and not all([args.game_dir, args.bitness, args.dxvk_version])
    )
    if run_update_check:
        if not check_for_update(session, SCRIPT_VERSION):
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
            return

    print(f"{Fore.YELLOW}\nWelcome to the DXVK Installation Script!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This script will help you install DXVK for your game.{Style.RESET_ALL}")

    game_dir = args.game_dir if args.game_dir else pathlib.Path(prompt_game_directory())
    bitness  = args.bitness  if args.bitness  else prompt_bitness()

    if args.dxvk_version:
        dxvk_version, dlls = args.dxvk_version
    else:
        dxvk_version, dlls = detect_dxvk_version(game_dir)
        if not dxvk_version:
            dxvk_version, dlls = prompt_dxvk_version()

    installer = DXVKInstaller(game_dir, bitness, dxvk_version, dlls, args.dxvk_release, session)

    try:
        installer.install()
    except InstallationCancelled as e:
        print(f"{Fore.YELLOW}Installation cancelled: {e}{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")