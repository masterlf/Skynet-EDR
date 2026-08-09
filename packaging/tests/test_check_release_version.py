from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPOSITORY_ROOT / "packaging" / "scripts" / "check-release-version.py"
FIXTURE_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "packaging/nfpm.yaml",
    "integrations/hermes/skynet-edr/__init__.py",
    "integrations/hermes/skynet-edr/plugin.yaml",
    "integrations/hermes/skynet-edr/dashboard/manifest.json",
    "crates/skynet-edr-core/Cargo.toml",
    "crates/skynet-edr-cli/Cargo.toml",
    "crates/skynet-edr-daemon/Cargo.toml",
    "crates/skynet-edr-mcp/Cargo.toml",
    "docs/releases/v0.5.0.md",
    "README.md",
    "docs/ROADMAP.md",
    "docs/INSTALL.md",
    "CHANGELOG.md",
)


def load_checker():
    spec = importlib.util.spec_from_file_location("check_release_version", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load release version checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseVersionCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.fixture_root = Path(self.temp_dir.name)
        for relative in FIXTURE_FILES:
            destination = self.fixture_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPOSITORY_ROOT / relative, destination)
        for member in (
            "skynet-edr-core",
            "skynet-edr-cli",
            "skynet-edr-daemon",
            "skynet-edr-mcp",
        ):
            source_directory = self.fixture_root / "crates" / member / "src"
            source_directory.mkdir(parents=True, exist_ok=True)
            (source_directory / "lib.rs").write_text("", encoding="utf-8")
            (source_directory / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        self.checker = load_checker()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def make_cargo_fixture_self_contained(self) -> None:
        manifests = {
            "skynet-edr-core": "",
            "skynet-edr-cli": (
                "[dependencies]\n"
                'skynet-edr-core = { version = "0.5.0", path = "../skynet-edr-core" }\n'
            ),
            "skynet-edr-daemon": (
                "[dependencies]\n"
                'skynet-edr-core = { version = "0.5.0", path = "../skynet-edr-core" }\n'
                'skynet-edr-mcp = { version = "0.5.0", path = "../skynet-edr-mcp" }\n'
                "\n[dev-dependencies]\n"
            ),
            "skynet-edr-mcp": (
                "[dependencies]\n"
                'skynet-edr-core = { version = "0.5.0", path = "../skynet-edr-core" }\n'
            ),
        }
        for package_name, dependencies in manifests.items():
            (self.fixture_root / f"crates/{package_name}/Cargo.toml").write_text(
                "[package]\n"
                f'name = "{package_name}"\n'
                "version.workspace = true\n"
                "edition.workspace = true\n"
                f"\n{dependencies}",
                encoding="utf-8",
            )

    def refresh_lock(self) -> None:
        result = subprocess.run(
            ["cargo", "generate-lockfile", "--offline"],
            cwd=self.fixture_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.fail(f"could not refresh fixture lockfile: {result.stderr}")

    def run_checker(self, *arguments: str) -> None:
        with (
            mock.patch.object(self.checker, "ROOT", self.fixture_root),
            mock.patch.object(sys, "argv", [str(CHECKER_PATH), *arguments]),
        ):
            self.checker.main()

    def test_rejects_duplicate_python_plugin_version_assignments(self) -> None:
        plugin = self.fixture_root / "integrations/hermes/skynet-edr/__init__.py"
        duplicate_assignments = (
            'PLUGIN_VERSION = "0.5.0"',
            'PLUGIN_VERSION = "9.9.9"',
            'if True:\n    PLUGIN_VERSION = "9.9.9"',
            'PLUGIN_VERSION += ".hostile"',
            "try:\n    raise RuntimeError\nexcept RuntimeError as PLUGIN_VERSION:\n    pass",
            (
                "class HostileVersion:\n"
                "    global PLUGIN_VERSION\n"
                '    PLUGIN_VERSION = "9.9.9"'
            ),
        )
        for duplicate_assignment in duplicate_assignments:
            with self.subTest(duplicate_assignment=duplicate_assignment):
                original = plugin.read_text(encoding="utf-8")
                plugin.write_text(
                    original + f"\n{duplicate_assignment}\n",
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn("duplicate Hermes plugin version", str(failure.exception))
                finally:
                    plugin.write_text(original, encoding="utf-8")

    def test_rejects_dynamic_python_plugin_version_rebinding(self) -> None:
        plugin = self.fixture_root / "integrations/hermes/skynet-edr/__init__.py"
        rebindings = (
            'exec("PLUGIN_VERSION = \'9.9.9\'")',
            'globals()["PLUGIN_VERSION"] = "9.9.9"',
            'vars()["PLUGIN_VERSION"] = "9.9.9"',
        )
        for rebinding in rebindings:
            with self.subTest(rebinding=rebinding):
                original = plugin.read_text(encoding="utf-8")
                plugin.write_text(original + f"\n{rebinding}\n", encoding="utf-8")
                try:
                    runtime = {
                        "__file__": str(plugin),
                        "__name__": "hostile_plugin_fixture",
                    }
                    exec(compile(plugin.read_text(encoding="utf-8"), plugin, "exec"), runtime)
                    self.assertEqual(runtime["PLUGIN_VERSION"], "9.9.9")

                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn("unsafe Hermes plugin version", str(failure.exception))
                finally:
                    plugin.write_text(original, encoding="utf-8")

    def test_rejects_unsafe_python_namespace_mutation_surfaces(self) -> None:
        plugin = self.fixture_root / "integrations/hermes/skynet-edr/__init__.py"
        unsafe_surfaces = (
            "namespace = globals",
            'locals()["PLUGIN_VERSION"] = "9.9.9"',
            'eval("PLUGIN_VERSION")',
            'compile("PLUGIN_VERSION = \'9.9.9\'", "<hostile>", "exec")',
            'setattr(module, "PLUGIN_VERSION", "9.9.9")',
            'delattr(module, "PLUGIN_VERSION")',
            'import builtins as hostile_builtins\nhostile_builtins.exec("pass")',
            'from builtins import exec as run\nrun("pass")',
            '__builtins__["exec"]("pass")',
            'module.__dict__["PLUGIN_VERSION"] = "9.9.9"',
            'module.PLUGIN_VERSION = "9.9.9"',
            "del module.PLUGIN_VERSION",
        )
        for unsafe_surface in unsafe_surfaces:
            with self.subTest(unsafe_surface=unsafe_surface):
                original = plugin.read_text(encoding="utf-8")
                plugin.write_text(
                    original + f"\n{unsafe_surface}\n",
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn("unsafe Hermes plugin version", str(failure.exception))
                finally:
                    plugin.write_text(original, encoding="utf-8")

    def test_rejects_duplicate_plugin_yaml_version_keys(self) -> None:
        manifest = self.fixture_root / "integrations/hermes/skynet-edr/plugin.yaml"
        for duplicate_key, duplicate_value in (
            ("version", '"0.5.0"'),
            ("version", '"9.9.9"'),
            ("version", "9.9.9"),
            ('"version"', '"9.9.9"'),
        ):
            with self.subTest(duplicate_value=duplicate_value):
                original = manifest.read_text(encoding="utf-8")
                manifest.write_text(
                    original + f"\n{duplicate_key}: {duplicate_value}\n",
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn(
                        "duplicate Hermes plugin manifest version",
                        str(failure.exception),
                    )
                finally:
                    manifest.write_text(original, encoding="utf-8")

        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            + '\n? version\n: "9.9.9"\n',
            encoding="utf-8",
        )
        with self.assertRaises(SystemExit) as failure:
            self.run_checker()
        self.assertIn("unsupported root YAML syntax", str(failure.exception))

    def test_rejects_duplicate_nfpm_version_keys(self) -> None:
        manifest = self.fixture_root / "packaging/nfpm.yaml"
        for duplicate_key, duplicate_value in (
            ("version", "${SKYNET_EDR_VERSION:-0.5.0}"),
            ("version", "${SKYNET_EDR_VERSION:-9.9.9}"),
            ("version", "9.9.9"),
            ('"version"', "9.9.9"),
        ):
            with self.subTest(duplicate_value=duplicate_value):
                original = manifest.read_text(encoding="utf-8")
                manifest.write_text(
                    original + f"\n{duplicate_key}: {duplicate_value}\n",
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn("duplicate nFPM default version", str(failure.exception))
                finally:
                    manifest.write_text(original, encoding="utf-8")

        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            + '\n? version\n: "9.9.9"\n',
            encoding="utf-8",
        )
        with self.assertRaises(SystemExit) as failure:
            self.run_checker()
        self.assertIn("unsupported root YAML syntax", str(failure.exception))

    def test_rejects_duplicate_dashboard_json_version_keys(self) -> None:
        manifest = (
            self.fixture_root
            / "integrations/hermes/skynet-edr/dashboard/manifest.json"
        )
        for duplicate_version in ("0.5.0", "9.9.9"):
            with self.subTest(duplicate_version=duplicate_version):
                original = manifest.read_text(encoding="utf-8")
                manifest.write_text(
                    original.replace(
                        '"version": "0.5.0",',
                        '"version": "0.5.0",\n'
                        f'  "version": "{duplicate_version}",',
                        1,
                    ),
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn("duplicate JSON key", str(failure.exception))
                finally:
                    manifest.write_text(original, encoding="utf-8")

    def test_rejects_unexpected_internal_prefixed_cargo_lock_identity(self) -> None:
        lockfile = self.fixture_root / "Cargo.lock"
        with lockfile.open("a", encoding="utf-8") as lock:
            lock.write(
                '\n[[package]]\nname = "skynet-edr-ghost"\nversion = "0.4.1"\n'
            )

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn(
            "unexpected internal packages in Cargo.lock: skynet-edr-ghost",
            str(failure.exception),
        )

    def test_rejects_mismatch_in_each_internal_dependency(self) -> None:
        dependencies = (
            ("skynet-edr-cli", "skynet-edr-core"),
            ("skynet-edr-daemon", "skynet-edr-core"),
            ("skynet-edr-daemon", "skynet-edr-mcp"),
            ("skynet-edr-mcp", "skynet-edr-core"),
        )
        for crate, dependency in dependencies:
            with self.subTest(crate=crate, dependency=dependency):
                manifest = self.fixture_root / f"crates/{crate}/Cargo.toml"
                original = manifest.read_text(encoding="utf-8")
                manifest.write_text(
                    original.replace(
                        f'{dependency} = {{ version = "0.5.0"',
                        f'{dependency} = {{ version = "9.9.9"',
                    ),
                    encoding="utf-8",
                )

                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn(f"{dependency}=9.9.9", str(failure.exception))
                finally:
                    manifest.write_text(original, encoding="utf-8")

    def test_rejects_explicit_empty_expected_version(self) -> None:
        with self.assertRaises(SystemExit) as failure:
            self.run_checker("--expected", "")

        self.assertIn("invalid release version", str(failure.exception))

    def test_rejects_reordered_internal_dependency_version(self) -> None:
        daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
        daemon_manifest.write_text(
            daemon_manifest.read_text(encoding="utf-8").replace(
                'skynet-edr-core = { version = "0.5.0", path = "../skynet-edr-core" }',
                'skynet-edr-core = { path = "../skynet-edr-core", version = "9.9.9" }',
            ),
            encoding="utf-8",
        )

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn("skynet-edr-core=9.9.9", str(failure.exception))

    def test_rejects_target_specific_duplicate_internal_dependency(self) -> None:
        daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
        with daemon_manifest.open("a", encoding="utf-8") as manifest:
            manifest.write(
                "\n[target.'cfg(unix)'.dependencies]\n"
                'skynet-edr-core = { path = "../skynet-edr-core", version = "9.9.9" }\n'
            )

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn("target.cfg(unix).dependencies skynet-edr-core=9.9.9", str(failure.exception))

    def test_rejects_internal_path_dependency_without_version(self) -> None:
        daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
        daemon_manifest.write_text(
            daemon_manifest.read_text(encoding="utf-8").replace(
                'skynet-edr-core = { version = "0.5.0", path = "../skynet-edr-core" }',
                'skynet-edr-core = { path = "../skynet-edr-core" }',
            ),
            encoding="utf-8",
        )

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn("missing version for internal dependency", str(failure.exception))

    def test_rejects_mismatched_workspace_inherited_internal_dependency(self) -> None:
        workspace_manifest = self.fixture_root / "Cargo.toml"
        with workspace_manifest.open("a", encoding="utf-8") as manifest:
            manifest.write(
                "\n[workspace.dependencies]\n"
                'skynet-edr-core = { path = "crates/skynet-edr-core", version = "9.9.9" }\n'
            )
        daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
        daemon_manifest.write_text(
            daemon_manifest.read_text(encoding="utf-8").replace(
                'skynet-edr-core = { version = "0.5.0", path = "../skynet-edr-core" }',
                "skynet-edr-core = { workspace = true }",
            ),
            encoding="utf-8",
        )

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn("workspace.dependencies skynet-edr-core=9.9.9", str(failure.exception))

    def test_rejects_internal_dependency_in_implicit_root_package(self) -> None:
        self.make_cargo_fixture_self_contained()
        workspace_manifest = self.fixture_root / "Cargo.toml"
        with workspace_manifest.open("a", encoding="utf-8") as manifest:
            manifest.write(
                "\n[package]\n"
                'name = "skynet-edr-root"\n'
                "version.workspace = true\n"
                "edition.workspace = true\n"
                "\n[dependencies]\n"
                'skynet-edr-core = { path = "crates/skynet-edr-core", version = ">=0.4.0" }\n'
            )
        source_directory = self.fixture_root / "src"
        source_directory.mkdir()
        (source_directory / "lib.rs").write_text("", encoding="utf-8")
        self.refresh_lock()

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn("skynet-edr-root dependencies skynet-edr-core=>=0.4.0", str(failure.exception))

    def test_rejects_internal_dependency_in_implicit_path_member(self) -> None:
        self.make_cargo_fixture_self_contained()
        implicit_root = self.fixture_root / "crates/skynet-edr-implicit"
        (implicit_root / "src").mkdir(parents=True)
        (implicit_root / "src/lib.rs").write_text("", encoding="utf-8")
        (implicit_root / "Cargo.toml").write_text(
            "[package]\n"
            'name = "skynet-edr-implicit"\n'
            "version.workspace = true\n"
            "edition.workspace = true\n"
            "\n[dependencies]\n"
            'skynet-edr-core = { path = "../skynet-edr-core", version = ">=0.4.0" }\n',
            encoding="utf-8",
        )
        daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
        daemon_manifest.write_text(
            daemon_manifest.read_text(encoding="utf-8").replace(
                "[dev-dependencies]\n",
                "[dev-dependencies]\n"
                'skynet-edr-implicit = { path = "../skynet-edr-implicit", version = "0.5.0" }\n',
            ),
            encoding="utf-8",
        )
        self.refresh_lock()

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn(
            "skynet-edr-implicit dependencies skynet-edr-core=>=0.4.0",
            str(failure.exception),
        )

    def test_rejects_symlinked_workspace_member_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as external_directory:
            external_root = Path(external_directory)
            (external_root / "Cargo.toml").write_text(
                "[package]\n"
                'name = "external-member"\n'
                'version = "0.4.1"\n'
                'edition = "2021"\n',
                encoding="utf-8",
            )
            (external_root / "src").mkdir()
            (external_root / "src/lib.rs").write_text("", encoding="utf-8")
            (self.fixture_root / "linked-member").symlink_to(
                external_root,
                target_is_directory=True,
            )
            workspace_manifest = self.fixture_root / "Cargo.toml"
            workspace_manifest.write_text(
                workspace_manifest.read_text(encoding="utf-8").replace(
                    '    "crates/skynet-edr-mcp",\n',
                    '    "crates/skynet-edr-mcp",\n    "linked-member",\n',
                ),
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit):
                self.run_checker()

    def test_rejects_symlinked_path_dependency_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as external_directory:
            external_root = Path(external_directory)
            (external_root / "Cargo.toml").write_text(
                "[package]\n"
                'name = "external-dependency"\n'
                'version = "1.0.0"\n'
                'edition = "2021"\n',
                encoding="utf-8",
            )
            (external_root / "src").mkdir()
            (external_root / "src/lib.rs").write_text("", encoding="utf-8")
            (self.fixture_root / "linked-dependency").symlink_to(
                external_root,
                target_is_directory=True,
            )
            daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
            daemon_manifest.write_text(
                daemon_manifest.read_text(encoding="utf-8").replace(
                    "[dev-dependencies]\n",
                    "[dev-dependencies]\n"
                    'external-dependency = { path = "../../linked-dependency", version = "1.0.0" }\n',
                ),
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit):
                self.run_checker()

    def test_rejects_underscore_alias_for_internal_dependency(self) -> None:
        daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
        daemon_manifest.write_text(
            daemon_manifest.read_text(encoding="utf-8").replace(
                'skynet-edr-core = { version = "0.5.0", path = "../skynet-edr-core" }',
                'skynet_edr_core = { version = ">=0.4", path = "../skynet-edr-core" }',
            ),
            encoding="utf-8",
        )

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn(
            "skynet_edr_core package skynet-edr-core=>=0.4",
            str(failure.exception),
        )

    def test_rejects_internal_package_manifest_version_mismatch(self) -> None:
        cli_manifest = self.fixture_root / "crates/skynet-edr-cli/Cargo.toml"
        cli_manifest.write_text(
            cli_manifest.read_text(encoding="utf-8").replace(
                "version.workspace = true",
                'version = "9.9.9"',
            ),
            encoding="utf-8",
        )

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn("skynet-edr-cli package version=9.9.9", str(failure.exception))

    def test_rejects_duplicate_internal_cargo_lock_entries(self) -> None:
        lockfile = self.fixture_root / "Cargo.lock"
        current_entry = '[[package]]\nname = "skynet-edr-core"\nversion = "0.5.0"'
        lockfile.write_text(
            lockfile.read_text(encoding="utf-8").replace(
                current_entry,
                '[[package]]\nname = "skynet-edr-core"\nversion = "0.3.0"\n\n'
                f"{current_entry}",
                1,
            ),
            encoding="utf-8",
        )

        with self.assertRaises(SystemExit):
            self.run_checker()

    def test_rejects_external_root_manifest_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as external_directory:
            external_manifest = Path(external_directory) / "Cargo.toml"
            external_manifest.write_text("this is not TOML = [", encoding="utf-8")
            fixture_manifest = self.fixture_root / "Cargo.toml"
            fixture_manifest.unlink()
            fixture_manifest.symlink_to(external_manifest)

            with self.assertRaises(SystemExit) as failure:
                self.run_checker()

            self.assertIn("Cargo manifest escapes repository", str(failure.exception))

    def test_packaging_builds_lock_metadata_and_compilation(self) -> None:
        for relative_path in (
            "packaging/scripts/build-tarball.sh",
            "packaging/scripts/build-packages.sh",
        ):
            with self.subTest(script=relative_path):
                script = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn(
                    "cargo metadata --locked --no-deps --format-version 1",
                    script,
                )
                self.assertIn(
                    "cargo build --locked --release --workspace --bins",
                    script,
                )


if __name__ == "__main__":
    unittest.main()
