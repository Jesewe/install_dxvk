import os
import sys
import requests
import tarfile
import shutil
import tempfile
import pathlib
import orjson
import argparse
from tqdm import tqdm
from colorama import init, Fore, Style
from dxvk_utils import (
    prompt_game_directory, prompt_bitness, prompt_dxvk_version,
    prompt_yes_no, detect_dxvk_version, validate_dxvk_version,
    validate_bitness, validate_directory, validate_dxvk_release,
    get_existing_dxvk_version, check_for_update, DXVK_VERSION_MAP,
    ALL_DXVK_DLLS, DEFAULT_HTTP_TIMEOUT,
)

# Enable ANSI color escape sequence parsing on Windows console
init()

# Local version tag used for GitHub release comparisons and User-Agent headers
SCRIPT_VERSION = "v1.0.5"

class InstallationCancelled(Exception):
    """Raised when the user declines to proceed with installation or overwrite."""

class ReleaseFetchError(Exception):
    """Raised when release metadata or asset URL cannot be retrieved."""

class ExtractionError(Exception):
    """Raised when release archive downloading or extraction fails."""

class InstallationError(Exception):
    """Raised when required DLLs or directories cannot be copied."""

class DXVKInstaller:
    def __init__(self, game_dir, bitness, dxvk_version, dlls, dxvk_release=None, session=None, overwrite=None, confirm_callback=None):
        self.game_dir         = pathlib.Path(game_dir)
        self.bitness          = bitness
        self.dxvk_version     = dxvk_version
        self.dlls             = dlls
        self.dxvk_release     = dxvk_release
        self.session          = session or requests.Session()
        self.overwrite        = overwrite
        self.confirm_callback = confirm_callback or prompt_yes_no
        self.target_dir       = (
            self.game_dir / 'system32'
            if (self.game_dir / 'system32').exists()
            else self.game_dir
        )

    def download_file(self, url, dest_path):
        """Download a file with a progress bar."""
        response = self.session.get(url, stream=True, timeout=DEFAULT_HTTP_TIMEOUT)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        # Stream chunk size for responsive progress bar updates
        block_size = 64 * 1024
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
        try:
            response = self.session.get(api_url, timeout=DEFAULT_HTTP_TIMEOUT)
            response.raise_for_status()
            data    = orjson.loads(response.content)
            version = data['tag_name']
            for asset in data.get('assets', []):
                if asset['name'].endswith('.tar.gz'):
                    return asset['browser_download_url'], asset['name'], version
        except Exception as e:
            raise ReleaseFetchError(f"Failed to fetch DXVK release from GitHub: {e}") from e

        raise ReleaseFetchError("No .tar.gz asset found in the DXVK release.")

    def _remove_existing_dlls(self):
        """Remove existing DXVK DLLs from the target and syswow64 directories."""
        for dll in ALL_DXVK_DLLS:
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
        """Check for existing DXVK DLLs and prompt or check overwrite policy."""
        existing_version, existing_dlls = get_existing_dxvk_version(
            self.target_dir, self.game_dir, self.bitness
        )

        if not existing_dlls:
            return

        print(
            f"{Fore.YELLOW}Existing DXVK version ({existing_version}) found "
            f"with DLLs: {', '.join(existing_dlls)}{Style.RESET_ALL}"
        )

        if self.overwrite is True:
            self._remove_existing_dlls()
            return

        if self.overwrite is False:
            raise InstallationCancelled("Declined to overwrite existing installation.")

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

        if self.confirm_callback(question):
            self._remove_existing_dlls()
        else:
            raise InstallationCancelled("User declined to overwrite existing installation.")

    def _download_and_extract_release(self, download_url, release_name, tmp_dir):
        """Download and extract the DXVK release tarball."""
        tar_path = os.path.join(tmp_dir, release_name)

        try:
            self.download_file(download_url, tar_path)
        except Exception as e:
            raise ExtractionError(f"Failed to download DXVK release archive: {e}") from e

        print(f"{Fore.YELLOW}Extracting archive...{Style.RESET_ALL}")
        try:
            with tarfile.open(tar_path, 'r:gz') as tar:
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(tmp_dir, filter='data')
                else:
                    tar.extractall(tmp_dir)
        except Exception as e:
            raise ExtractionError(f"Failed to extract archive: {e}") from e

        dxvk_dir = os.path.join(tmp_dir, release_name.replace('.tar.gz', ''))
        if not os.path.isdir(dxvk_dir):
            raise ExtractionError("DXVK directory not found in extracted archive.")

        return dxvk_dir

    def _copy_files(self, dxvk_dir):
        """Copy the necessary DLLs and config file to the target directory."""
        self.target_dir.mkdir(parents=True, exist_ok=True)

        src_dir = os.path.join(dxvk_dir, self.bitness)
        for dll in self.dlls:
            src_path = os.path.join(src_dir, dll)
            if not os.path.isfile(src_path):
                raise InstallationError(f"DLL {dll} not found in {src_dir}.")
            shutil.copy(src_path, self.target_dir / dll)
            print(f"{Fore.CYAN}Copied {dll} to {self.target_dir / dll}{Style.RESET_ALL}")

        if self.bitness == 'x64' and (self.game_dir / 'syswow64').exists():
            syswow64_dir  = self.game_dir / 'syswow64'
            syswow64_dir.mkdir(parents=True, exist_ok=True)
            src_dir_x32   = os.path.join(dxvk_dir, 'x32')
            if not os.path.isdir(src_dir_x32):
                raise InstallationError(f"32-bit DLL directory not found in {dxvk_dir}.")
            for dll in self.dlls:
                src_path = os.path.join(src_dir_x32, dll)
                if not os.path.isfile(src_path):
                    raise InstallationError(f"DLL {dll} not found in {src_dir_x32}.")
                shutil.copy(src_path, syswow64_dir / dll)
                print(f"{Fore.CYAN}Copied {dll} to {syswow64_dir / dll}{Style.RESET_ALL}")

        dxvk_conf_src = os.path.join(dxvk_dir, 'dxvk.conf')
        if os.path.isfile(dxvk_conf_src):
            shutil.copy(dxvk_conf_src, self.target_dir / 'dxvk.conf')
            print(f"{Fore.CYAN}Copied dxvk.conf to {self.target_dir / 'dxvk.conf'}{Style.RESET_ALL}")

    def install(self):
        """Install DXVK by downloading, extracting, and copying DLLs."""
        download_url, release_name, latest_version = self.fetch_release()
        print(f"{Fore.GREEN}Found release: {release_name} (version {latest_version}){Style.RESET_ALL}")

        self.check_existing(latest_version)

        with tempfile.TemporaryDirectory() as tmp_dir:
            dxvk_dir = self._download_and_extract_release(download_url, release_name, tmp_dir)
            self._copy_files(dxvk_dir)

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
            return latest_version

def main():
    parser = argparse.ArgumentParser(description="DXVK Installation Script")
    parser.add_argument('--game-dir',        type=validate_directory,    help="Path to the game directory")
    parser.add_argument('--bitness',         type=validate_bitness,      choices=['x32', 'x64'], help="Bitness (x32 or x64)")
    parser.add_argument('--dxvk-version',    type=validate_dxvk_version, help="DXVK version (d3d8, d3d9, d3d10, d3d11)")
    parser.add_argument('--dxvk-release',    type=validate_dxvk_release, help="Specific DXVK release version (e.g. v2.3 or v2.3.1)")
    parser.add_argument('--check-update',    action='store_true',        help="Check for script updates")
    parser.add_argument('--no-update-check', action='store_true',        help="Skip checking for script updates")
    parser.add_argument('--yes', '-y',       action='store_true',        help="Automatically overwrite existing DLLs without prompt")

    args = parser.parse_args()

    is_interactive = not all([args.game_dir, args.bitness, args.dxvk_version])

    session = requests.Session()
    session.headers.update({'User-Agent': f'DXVK-Installer/{SCRIPT_VERSION}'})

    run_update_check = args.check_update or (
        not args.no_update_check and is_interactive
    )
    if run_update_check:
        if not check_for_update(session, SCRIPT_VERSION):
            if is_interactive:
                input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
            return 0

    print(f"{Fore.YELLOW}\nWelcome to the DXVK Installation Script!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This script will help you install DXVK for your game.{Style.RESET_ALL}")

    try:
        game_dir = args.game_dir if args.game_dir else pathlib.Path(prompt_game_directory())
        bitness  = args.bitness  if args.bitness  else prompt_bitness()

        if args.dxvk_version:
            dxvk_version, dlls = args.dxvk_version
        else:
            dxvk_version, dlls = detect_dxvk_version(game_dir)
            if not dxvk_version:
                dxvk_version, dlls = prompt_dxvk_version()

        overwrite = True if args.yes else None
        installer = DXVKInstaller(game_dir, bitness, dxvk_version, dlls, args.dxvk_release, session, overwrite=overwrite)
        installer.install()

        if is_interactive:
            input(f"{Fore.GREEN}Installation complete. Press Enter to exit...{Style.RESET_ALL}")
        return 0

    except InstallationCancelled as e:
        print(f"{Fore.YELLOW}Installation cancelled: {e}{Style.RESET_ALL}")
        if is_interactive:
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
        return 0

    except (ReleaseFetchError, ExtractionError, InstallationError) as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        if is_interactive:
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
        return 1

    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        if is_interactive:
            input(f"{Fore.GREEN}Press Enter to exit...{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    sys.exit(main())