import os
import re
import pathlib
import argparse
import glob
import pefile
from colorama import Fore, Style

# Single source of truth for the DXVK version required DLLs mapping.
DXVK_VERSION_MAP = {
    'd3d8':  ['d3d8.dll', 'd3d9.dll'],
    'd3d9':  ['d3d9.dll'],
    'd3d10': ['d3d10core.dll', 'd3d11.dll', 'dxgi.dll'],
    'd3d11': ['d3d11.dll', 'dxgi.dll'],
}

# Detection order for get_existing_dxvk_version: check DLL supersets before subsets
# so that d3d8 (which includes d3d9.dll) is matched before d3d9, and d3d10
# (which includes d3d11.dll + dxgi.dll) is matched before d3d11.
_EXISTING_DETECTION_ORDER = ['d3d8', 'd3d10', 'd3d9', 'd3d11']

# Explicit numeric priority so detection never relies on string ordering.
VERSION_PRIORITY = {'d3d8': 0, 'd3d9': 1, 'd3d10': 2, 'd3d11': 3}

# Reverse map: each DLL → the version that introduced it.
_DLL_TO_VERSION = {
    'd3d8.dll':     'd3d8',
    'd3d9.dll':     'd3d9',
    'd3d10core.dll':'d3d10',
    'd3d11.dll':    'd3d11',
    'dxgi.dll':     'd3d11',  # shared by d3d10 and d3d11; priority resolves ties
}

def compare_versions(current_version, latest_version):
    """Compare two version strings (e.g. 'v1.0.0' vs 'v1.0.1').
    Returns -1 if current < latest, 0 if equal, 1 if current > latest."""
    def parse_version(version):
        version = version.lstrip('v')
        return [int(x) for x in version.split('.')]

    current = parse_version(current_version)
    latest  = parse_version(latest_version)

    max_len = max(len(current), len(latest))
    current.extend([0] * (max_len - len(current)))
    latest.extend( [0] * (max_len - len(latest)))

    for c, l in zip(current, latest):
        if c < l:
            return -1
        if c > l:
            return 1
    return 0

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
        if bitness in ('x32', 'x64'):
            return bitness
        print(f"{Fore.RED}Invalid input. Please enter 'x32' or 'x64'.{Style.RESET_ALL}")

def prompt_dxvk_version():
    """Prompt the user for the DXVK version (D3D8, D3D9, D3D10, D3D11)."""
    # Build the menu from DXVK_VERSION_MAP so adding a new version only
    # requires updating the map.
    options = list(reversed(list(DXVK_VERSION_MAP.items())))  # display d3d8 first
    options = [
        ('d3d8',  DXVK_VERSION_MAP['d3d8']),
        ('d3d9',  DXVK_VERSION_MAP['d3d9']),
        ('d3d10', DXVK_VERSION_MAP['d3d10']),
        ('d3d11', DXVK_VERSION_MAP['d3d11']),
    ]

    while True:
        print(f"\n{Fore.YELLOW}Available DXVK versions:{Style.RESET_ALL}")
        for idx, (version, dlls) in enumerate(options, start=1):
            print(f"{Fore.CYAN}{idx}. {version.upper()} (requires {', '.join(dlls)}){Style.RESET_ALL}")
        choice = input(f"{Fore.GREEN}Select DXVK version (1-{len(options)}): {Style.RESET_ALL}").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            version, dlls = options[int(choice) - 1]
            return version, dlls
        print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and {len(options)}.{Style.RESET_ALL}")

def detect_dxvk_version(game_dir):
    """Auto-detect the required DXVK version by analyzing .exe files in the game directory."""
    exe_files = glob.glob(os.path.join(game_dir, "*.exe"))
    if not exe_files:
        print(f"{Fore.YELLOW}No .exe files found in {game_dir}. Falling back to manual selection.{Style.RESET_ALL}")
        return None, None

    best_priority = -1
    detected_dlls = set()

    for exe in exe_files:
        try:
            pe = pefile.PE(exe, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            )
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='replace').lower()
                    if dll_name in _DLL_TO_VERSION:
                        detected_dlls.add(dll_name)
                        priority = VERSION_PRIORITY[_DLL_TO_VERSION[dll_name]]
                        if priority > best_priority:
                            best_priority = priority
            pe.close()
        except Exception as e:
            print(f"{Fore.YELLOW}Failed to analyze {exe}: {e}{Style.RESET_ALL}")

        if best_priority == VERSION_PRIORITY['d3d11']:
            break

    if best_priority < 0:
        print(f"{Fore.YELLOW}No Direct3D DLLs detected in .exe files. Falling back to manual selection.{Style.RESET_ALL}")
        return None, None

    detected_version = next(
        v for v, p in VERSION_PRIORITY.items() if p == best_priority
    )
    print(
        f"{Fore.GREEN}Detected DXVK version: {detected_version} "
        f"based on DLLs: {', '.join(detected_dlls)}{Style.RESET_ALL}"
    )
    return detected_version, DXVK_VERSION_MAP[detected_version]

def validate_dxvk_version(version):
    """Validate DXVK version from a command-line argument."""
    # Single reference to DXVK_VERSION_MAP.
    key = version.lower()
    if key not in DXVK_VERSION_MAP:
        raise argparse.ArgumentTypeError(
            f"DXVK version must be one of: {', '.join(DXVK_VERSION_MAP)}"
        )
    return key, DXVK_VERSION_MAP[key]

def validate_bitness(bitness):
    """Validate bitness from a command-line argument."""
    if bitness.lower() not in ('x32', 'x64'):
        raise argparse.ArgumentTypeError("Bitness must be either x32 or x64")
    return bitness.lower()

def validate_directory(directory):
    """Validate game directory from a command-line argument."""
    if not os.path.isdir(directory):
        raise argparse.ArgumentTypeError(f"Directory '{directory}' does not exist")
    return pathlib.Path(directory)

def validate_dxvk_release(release):
    """Validate DXVK release version string (e.g. 'v2.3' or 'v2.3.1')."""
    # Use a proper regex instead of the hand-rolled character loop,
    # which accepted malformed strings like 'v...' or 'v1.'.
    if not re.fullmatch(r'v\d+(\.\d+)+', release):
        raise argparse.ArgumentTypeError(
            "DXVK release must be in the format 'vX.Y[.Z]' (e.g. v2.3 or v2.3.1)"
        )
    return release

def get_existing_dxvk_version(target_dir, game_dir, bitness):
    """Infer existing DXVK version based on DLL files in the target directory."""
    all_dlls = [dll for dlls in DXVK_VERSION_MAP.values() for dll in dlls]
    all_dlls = list(dict.fromkeys(all_dlls))  # deduplicate, preserve order

    existing_dlls = []
    for dll in all_dlls:
        if (target_dir / dll).exists():
            existing_dlls.append(dll)

    if bitness == 'x64' and (game_dir / 'syswow64').exists():
        syswow64_dir = game_dir / 'syswow64'
        for dll in all_dlls:
            if (syswow64_dir / dll).exists():
                existing_dlls.append(f"{dll} (syswow64)")

    # Determine version using superset-first order so that d3d8 (which
    # bundles d3d9.dll) is matched before the plain d3d9 entry, and d3d10
    # (which bundles d3d11.dll + dxgi.dll) is matched before d3d11.
    existing_version = None
    for version in _EXISTING_DETECTION_ORDER:
        dll_list = DXVK_VERSION_MAP[version]
        in_system32   = all((target_dir / dll).exists() for dll in dll_list)
        in_syswow64   = (
            bitness == 'x64'
            and (game_dir / 'syswow64').exists()
            and all((game_dir / 'syswow64' / dll).exists() for dll in dll_list)
        )
        if in_system32 or in_syswow64:
            existing_version = version
            break

    if existing_dlls and not existing_version:
        existing_version = "unknown (DLLs detected)"

    return existing_version, existing_dlls

def check_for_update(session, script_version):
    """Check for a newer version of the script via GitHub API.

    Args:
        session: A requests.Session instance (shared, with timeout configured).
        script_version: The current script version string (e.g. 'v1.0.4').

    Returns:
        True  — caller should proceed.
        False — user chose to abort (caller should exit).
    """
    print(f"{Fore.YELLOW}Checking for script updates...{Style.RESET_ALL}")
    try:
        api_url = "https://api.github.com/repos/Jesewe/install_dxvk/releases/latest"
        response = session.get(api_url)
        response.raise_for_status()
        import orjson
        data = orjson.loads(response.content)
        latest_version = data['tag_name']

        if compare_versions(script_version, latest_version) < 0:
            print(f"{Fore.GREEN}A newer version ({latest_version}) is available!{Style.RESET_ALL}")
            print(
                f"{Fore.GREEN}Release page: "
                f"https://github.com/Jesewe/install_dxvk/releases/latest{Style.RESET_ALL}"
            )
            open_browser = _prompt_yes_no("Would you like to open the release page in your browser?")
            if open_browser:
                import webbrowser
                webbrowser.open("https://github.com/Jesewe/install_dxvk/releases/latest")
                print(f"{Fore.YELLOW}Opened release page in browser. Please update the script.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Continuing with current version ({script_version}).{Style.RESET_ALL}")

            if not _prompt_yes_no(f"Continue with installation using current version ({script_version})?"):
                print(f"{Fore.YELLOW}Installation cancelled. Please update the script.{Style.RESET_ALL}")
                return False
        else:
            print(f"{Fore.GREEN}You are using the latest version ({script_version}).{Style.RESET_ALL}")
    except Exception as e:
        print(
            f"{Fore.YELLOW}Failed to check for updates: {e}. "
            f"Continuing with current version ({script_version}).{Style.RESET_ALL}"
        )
    return True


def _prompt_yes_no(message):
    """Shared yes/no prompt used by module-level helpers."""
    while True:
        choice = input(f"{Fore.GREEN}{message} (yes/no): {Style.RESET_ALL}").strip().lower()
        if choice in ('yes', 'y'):
            return True
        if choice in ('no', 'n'):
            return False
        print(f"{Fore.RED}Invalid input. Please enter 'yes' or 'no'.{Style.RESET_ALL}")