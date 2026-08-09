from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPOSITORY_ROOT / "packaging" / "scripts" / "validate-artifact-listing.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_artifact_listing", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load artifact listing validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DebListingPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = load_validator()

    def test_accepts_bounded_root_owned_payload(self) -> None:
        listing = "\n".join(
            (
                "drwxr-xr-x root/root 0 2026-08-09 00:00 ./",
                "drwxr-xr-x root/root 0 2026-08-09 00:00 ./usr/bin/",
                "-rwxr-xr-x root/root 42 2026-08-09 00:00 ./usr/bin/skynet-edr",
                "-rwxr-xr-x root/root 42 2026-08-09 00:00 ./usr/libexec/skynet-edr/deploy-verify",
                "drwxr-x--- root/skynet-edr 0 2026-08-09 00:00 ./etc/skynet-edr/",
                "-rw-r----- root/skynet-edr 42 2026-08-09 00:00 ./etc/skynet-edr/config.toml",
                "drwxr-xr-x root/root 0 2026-08-09 00:00 ./var/lib/",
                "drwxr-x--- skynet-edr/skynet-edr 0 2026-08-09 00:00 ./var/lib/skynet-edr/",
            )
        )
        self.assertEqual(self.validator.validate_deb_listing(listing), [])

    def test_requires_root_owned_non_writable_installed_verifier(self) -> None:
        missing = "drwxr-xr-x root/root 0 2026-08-09 00:00 ./"
        errors = self.validator.validate_deb_listing(missing)
        self.assertIn("missing required payload path 'usr/libexec/skynet-edr/deploy-verify'", errors)

        wrong_mode = "\n".join(
            (
                missing,
                "-rwxrwxr-x root/root 42 2026-08-09 00:00 ./usr/libexec/skynet-edr/deploy-verify",
            )
        )
        errors = self.validator.validate_deb_listing(wrong_mode)
        self.assertTrue(any("deploy-verify" in error and "mode" in error for error in errors), errors)

    def test_rejects_absolute_parent_and_unexpected_paths(self) -> None:
        for path in ("/var/lib/skynet-edr", "./usr/../var/lib/skynet-edr", "./home/operator/.ssh/key"):
            with self.subTest(path=path):
                listing = f"-rw-r--r-- root/root 1 2026-08-09 00:00 {path}"
                errors = self.validator.validate_deb_listing(listing)
                self.assertTrue(errors)

    def test_rejects_links_special_files_and_dangerous_modes(self) -> None:
        fixtures = (
            "lrwxrwxrwx root/root 0 2026-08-09 00:00 ./usr/bin/skynet-edr -> ../../var/lib/skynet-edr",
            "crw-r--r-- root/root 0 2026-08-09 00:00 ./usr/bin/device",
            "-rwsr-xr-x root/root 1 2026-08-09 00:00 ./usr/bin/skynet-edr",
            "-rwxrwxrwx root/root 1 2026-08-09 00:00 ./usr/bin/skynet-edr",
        )
        for listing in fixtures:
            with self.subTest(listing=listing):
                self.assertTrue(self.validator.validate_deb_listing(listing))

    def test_rejects_ambiguous_or_non_root_listing_records(self) -> None:
        fixtures = (
            "garbage",
            "-rwxr-xr-x skynet-edr/skynet-edr 1 2026-08-09 00:00 ./usr/bin/skynet-edr",
            "-rwxr-xr-x root/root 1 bad-date ./usr/bin/skynet-edr",
        )
        for listing in fixtures:
            with self.subTest(listing=listing):
                self.assertTrue(self.validator.validate_deb_listing(listing))
    def test_rejects_root_owned_persistent_state_payload(self) -> None:
        listing = "drwxr-x--- root/root 0 2026-08-09 00:00 ./var/lib/skynet-edr/"
        self.assertTrue(self.validator.validate_deb_listing(listing))


if __name__ == "__main__":
    unittest.main()
