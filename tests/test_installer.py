import os
import io
import tarfile
import tempfile
import pathlib
import unittest
from unittest.mock import MagicMock

from install_dxvk import (
    DXVKInstaller,
    InstallationCancelled,
    ReleaseFetchError,
    ExtractionError,
    InstallationError,
)
from dxvk_utils import DXVK_VERSION_MAP


def _create_mock_tar_bytes():
    """Create a minimal in-memory .tar.gz archive containing DXVK release files."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for bitness in ("x32", "x64"):
            for dll in ("d3d11.dll", "dxgi.dll"):
                content = f"{bitness} {dll}".encode("utf-8")
                tarinfo = tarfile.TarInfo(name=f"dxvk-2.3/{bitness}/{dll}")
                tarinfo.size = len(content)
                tar.addfile(tarinfo, io.BytesIO(content))

        conf_content = b"# sample dxvk.conf"
        conf_tarinfo = tarfile.TarInfo(name="dxvk-2.3/dxvk.conf")
        conf_tarinfo.size = len(conf_content)
        tar.addfile(conf_tarinfo, io.BytesIO(conf_content))

    buffer.seek(0)
    return buffer.getvalue()


class TestDXVKInstaller(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = pathlib.Path(self.temp_dir.name)
        self.session = MagicMock()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_fetch_release_success(self):
        response = MagicMock()
        response.content = b'''{
            "tag_name": "v2.3",
            "assets": [
                {"name": "dxvk-2.3.tar.gz", "browser_download_url": "https://example.com/dxvk-2.3.tar.gz"},
                {"name": "other_file.txt", "browser_download_url": "https://example.com/other"}
            ]
        }'''
        response.raise_for_status.return_value = None
        self.session.get.return_value = response

        installer = DXVKInstaller(
            self.game_dir, "x64", "d3d11", DXVK_VERSION_MAP["d3d11"], session=self.session
        )
        url, name, version = installer.fetch_release()
        self.assertEqual(url, "https://example.com/dxvk-2.3.tar.gz")
        self.assertEqual(name, "dxvk-2.3.tar.gz")
        self.assertEqual(version, "v2.3")

    def test_fetch_release_no_asset_error(self):
        response = MagicMock()
        response.content = b'{"tag_name": "v2.3", "assets": []}'
        response.raise_for_status.return_value = None
        self.session.get.return_value = response

        installer = DXVKInstaller(
            self.game_dir, "x64", "d3d11", DXVK_VERSION_MAP["d3d11"], session=self.session
        )
        with self.assertRaises(ReleaseFetchError):
            installer.fetch_release()

    def test_check_existing_overwrite_true(self):
        (self.game_dir / "d3d11.dll").touch()
        installer = DXVKInstaller(
            self.game_dir, "x64", "d3d11", DXVK_VERSION_MAP["d3d11"], overwrite=True
        )
        installer.check_existing("v2.3")
        self.assertFalse((self.game_dir / "d3d11.dll").exists())

    def test_check_existing_overwrite_false(self):
        (self.game_dir / "d3d11.dll").touch()
        installer = DXVKInstaller(
            self.game_dir, "x64", "d3d11", DXVK_VERSION_MAP["d3d11"], overwrite=False
        )
        with self.assertRaises(InstallationCancelled):
            installer.check_existing("v2.3")

    def test_copy_files(self):
        extract_dir = self.game_dir / "extracted" / "dxvk-2.3"
        (extract_dir / "x64").mkdir(parents=True)
        (extract_dir / "x64" / "d3d11.dll").write_text("dummy")
        (extract_dir / "x64" / "dxgi.dll").write_text("dummy")
        (extract_dir / "dxvk.conf").write_text("# config")

        installer = DXVKInstaller(
            self.game_dir, "x64", "d3d11", DXVK_VERSION_MAP["d3d11"]
        )
        installer._copy_files(extract_dir)

        self.assertTrue((self.game_dir / "d3d11.dll").exists())
        self.assertTrue((self.game_dir / "dxgi.dll").exists())
        self.assertTrue((self.game_dir / "dxvk.conf").exists())

    def test_end_to_end_install_mock(self):
        tar_bytes = _create_mock_tar_bytes()

        release_response = MagicMock()
        release_response.content = b'''{
            "tag_name": "v2.3",
            "assets": [
                {"name": "dxvk-2.3.tar.gz", "browser_download_url": "https://example.com/dxvk-2.3.tar.gz"}
            ]
        }'''
        release_response.raise_for_status.return_value = None

        download_response = MagicMock()
        download_response.headers = {"content-length": str(len(tar_bytes))}
        download_response.iter_content.return_value = [tar_bytes]
        download_response.raise_for_status.return_value = None

        self.session.get.side_effect = [release_response, download_response]

        installer = DXVKInstaller(
            self.game_dir, "x64", "d3d11", DXVK_VERSION_MAP["d3d11"], session=self.session
        )
        installed_version = installer.install()

        self.assertEqual(installed_version, "v2.3")
        self.assertTrue((self.game_dir / "d3d11.dll").exists())
        self.assertTrue((self.game_dir / "dxgi.dll").exists())


if __name__ == "__main__":
    unittest.main()
