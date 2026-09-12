import os
import tempfile
import pathlib
import argparse
import unittest
from unittest.mock import MagicMock, patch

from dxvk_utils import (
    compare_versions,
    validate_dxvk_release,
    validate_bitness,
    validate_dxvk_version,
    validate_directory,
    get_existing_dxvk_version,
    detect_dxvk_version,
    check_for_update,
    DXVK_VERSION_MAP,
    ALL_DXVK_DLLS,
)


class TestCompareVersions(unittest.TestCase):
    def test_version_ordering(self):
        self.assertEqual(compare_versions("v1.0.0", "v1.0.1"), -1)
        self.assertEqual(compare_versions("v1.0.1", "v1.0.0"), 1)
        self.assertEqual(compare_versions("v1.0.0", "v1.0.0"), 0)

    def test_version_lengths(self):
        self.assertEqual(compare_versions("v1.0", "v1.0.0"), 0)
        self.assertEqual(compare_versions("v2.3", "v2.3.1"), -1)
        self.assertEqual(compare_versions("v2.3.1", "v2.3"), 1)


class TestValidators(unittest.TestCase):
    def test_validate_dxvk_release_valid(self):
        self.assertEqual(validate_dxvk_release("v2.3"), "v2.3")
        self.assertEqual(validate_dxvk_release("v2.3.1"), "v2.3.1")
        self.assertEqual(validate_dxvk_release("v1.10.3"), "v1.10.3")

    def test_validate_dxvk_release_invalid(self):
        invalid_releases = ["2.3", "v", "v1.", "v..", "v1.a", "latest"]
        for rel in invalid_releases:
            with self.subTest(release=rel):
                with self.assertRaises(argparse.ArgumentTypeError):
                    validate_dxvk_release(rel)

    def test_validate_bitness(self):
        self.assertEqual(validate_bitness("x32"), "x32")
        self.assertEqual(validate_bitness("X64"), "x64")
        with self.assertRaises(argparse.ArgumentTypeError):
            validate_bitness("x86")

    def test_validate_dxvk_version(self):
        version, dlls = validate_dxvk_version("D3D11")
        self.assertEqual(version, "d3d11")
        self.assertEqual(dlls, DXVK_VERSION_MAP["d3d11"])

        with self.assertRaises(argparse.ArgumentTypeError):
            validate_dxvk_version("opengl")

    def test_validate_directory(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = validate_directory(tmp_dir)
            self.assertEqual(path, pathlib.Path(tmp_dir))

        with self.assertRaises(argparse.ArgumentTypeError):
            validate_directory("non_existent_dir_12345")


class TestExistingDxvkVersion(unittest.TestCase):
    def test_no_dlls(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_dir = pathlib.Path(tmp_dir)
            version, dlls = get_existing_dxvk_version(target_dir, target_dir, "x64")
            self.assertIsNone(version)
            self.assertEqual(dlls, [])

    def test_d3d8_superset_over_d3d9(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_dir = pathlib.Path(tmp_dir)
            (target_dir / "d3d8.dll").touch()
            (target_dir / "d3d9.dll").touch()
            version, dlls = get_existing_dxvk_version(target_dir, target_dir, "x64")
            self.assertEqual(version, "d3d8")
            self.assertIn("d3d8.dll", dlls)
            self.assertIn("d3d9.dll", dlls)

    def test_d3d10_superset_over_d3d11(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_dir = pathlib.Path(tmp_dir)
            (target_dir / "d3d10core.dll").touch()
            (target_dir / "d3d11.dll").touch()
            (target_dir / "dxgi.dll").touch()
            version, dlls = get_existing_dxvk_version(target_dir, target_dir, "x64")
            self.assertEqual(version, "d3d10")

    def test_syswow64_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            game_dir = pathlib.Path(tmp_dir)
            target_dir = game_dir / "system32"
            syswow64_dir = game_dir / "syswow64"
            target_dir.mkdir()
            syswow64_dir.mkdir()

            (syswow64_dir / "d3d11.dll").touch()
            (syswow64_dir / "dxgi.dll").touch()

            version, dlls = get_existing_dxvk_version(target_dir, game_dir, "x64")
            self.assertEqual(version, "d3d11")
            self.assertIn("d3d11.dll (syswow64)", dlls)


class TestDetectDxvkVersion(unittest.TestCase):
    def test_no_exe_files(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            version, dlls = detect_dxvk_version(tmp_dir)
            self.assertIsNone(version)
            self.assertIsNone(dlls)

    @patch("pefile.PE")
    def test_detect_d3d11_priority(self, mock_pe_class):
        with tempfile.TemporaryDirectory() as tmp_dir:
            exe_path = pathlib.Path(tmp_dir) / "game.exe"
            exe_path.touch()

            mock_entry1 = MagicMock()
            mock_entry1.dll = b"d3d9.dll"
            mock_entry2 = MagicMock()
            mock_entry2.dll = b"d3d11.dll"

            mock_pe_instance = MagicMock()
            mock_pe_instance.DIRECTORY_ENTRY_IMPORT = [mock_entry1, mock_entry2]
            mock_pe_class.return_value = mock_pe_instance

            version, dlls = detect_dxvk_version(tmp_dir)
            self.assertEqual(version, "d3d11")
            self.assertEqual(dlls, DXVK_VERSION_MAP["d3d11"])
            mock_pe_instance.close.assert_called()


class TestCheckForUpdate(unittest.TestCase):
    def test_already_latest(self):
        session = MagicMock()
        response = MagicMock()
        response.content = b'{"tag_name": "v1.0.5"}'
        response.raise_for_status.return_value = None
        session.get.return_value = response

        result = check_for_update(session, "v1.0.5")
        self.assertTrue(result)

    def test_network_failure_continues(self):
        session = MagicMock()
        session.get.side_effect = Exception("Connection timed out")

        result = check_for_update(session, "v1.0.5")
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
