from __future__ import annotations

import importlib.util
import re
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
    "docs/releases/v0.6.0-rc.1.md",
    "README.md",
    "docs/ROADMAP.md",
    "docs/INSTALL.md",
    "docs/MVP_SUPPORT_MATRIX.md",
    "docs/HERMES_ENROLLMENT.md",
    "packaging/scripts/skynet-edr-hermes-enroll.py",
    "CHANGELOG.md",
    "SECURITY.md",
    "docs/README.md",
    "docs/ARCHITECTURE.md",
    "docs/CONCEPTS.md",
    "docs/HERMES_PLUGIN_TELEMETRY.md",
    "docs/HERMES_EVENT_INGESTION.md",
    "docs/INTEGRATIONS.md",
    "docs/OPERATIONS.md",
    "integrations/hermes/skynet-edr/README.md",
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
        prerelease_native_replacements = {
            "packaging/nfpm.yaml": (
                ("${SKYNET_EDR_DEB_VERSION:-0.6.0}", "${SKYNET_EDR_DEB_VERSION:-0.6.0~rc.1}"),
            ),
            "docs/ROADMAP.md": (("(`0.6.0`)", "(`0.6.0~rc.1`)"),),
            "docs/INSTALL.md": (
                ("DEB and RPM report `0.6.0`", "DEB and RPM report `0.6.0~rc.1`"),
                ("Arch reports `0.6.0-1`", "Arch reports `0.6.0.rc.1-1`"),
            ),
        }
        for relative in FIXTURE_FILES:
            if relative in {"CHANGELOG.md", "docs/releases/v0.6.0-rc.1.md"}:
                continue
            path = self.fixture_root / relative
            current = path.read_text(encoding="utf-8")
            for stable, prerelease in prerelease_native_replacements.get(relative, ()):
                current = current.replace(stable, prerelease)
            current = re.sub(
                r"0\.6\.0(?!-(?:rc|beta|alpha|[0-9])|\.(?:rc|beta|alpha)|~|[0-9])",
                "0.6.0-rc.1",
                current,
            )
            current = current.replace(
                "is an installable stable SemVer evaluation release",
                "is an installable prerelease",
            ).replace(
                "pre-1.0 stable SemVer evaluation release",
                "prerelease",
            ).replace("` stable SemVer |", "` prerelease |")
            path.write_text(current, encoding="utf-8")
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
                'skynet-edr-core = { version = "0.6.0-rc.1", path = "../skynet-edr-core" }\n'
            ),
            "skynet-edr-daemon": (
                "[dependencies]\n"
                'skynet-edr-core = { version = "0.6.0-rc.1", path = "../skynet-edr-core" }\n'
                'skynet-edr-mcp = { version = "0.6.0-rc.1", path = "../skynet-edr-mcp" }\n'
                "\n[dev-dependencies]\n"
            ),
            "skynet-edr-mcp": (
                "[dependencies]\n"
                'skynet-edr-core = { version = "0.6.0-rc.1", path = "../skynet-edr-core" }\n'
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

    def test_rejects_stale_current_ingestion_document_claims(self) -> None:
        document = self.fixture_root / "docs/HERMES_EVENT_INGESTION.md"
        current = document.read_text(encoding="utf-8")
        current = current.replace(
            "live v0.4 integrations should emit `skynet.event.v0` events directly where possible.",
            "v0.6.0-rc.1 uses authenticated protocol-v3 live ingress for canonical events.",
        ).replace(
            "Ingestion is offline/read-only: it parses trace files and does not intercept live agent execution.",
            "Legacy trace and spool imports are offline/read-only; live ingress is passive.",
        ).replace(
            "Canonical live JSONL spool ingestion:",
            "Explicit canonical JSONL spool import:",
        ).replace(
            "Daemon startup can poll the same canonical spool when `[spool]` is enabled in the daemon config:",
            "The canonical spool CLI is an explicit offline import path.",
        ).replace(
            "The current end-to-end MVP has two built-in correlation rules:",
            "The current detector catalog includes narrow correlators and the canonical sequence rule pack:",
        )
        stale_claims = (
            "live v0.4 integrations should emit `skynet.event.v0` events directly where possible.",
            "Ingestion is offline/read-only: it parses trace files and does not intercept live agent execution.",
            "Canonical live JSONL spool ingestion:",
            "Daemon startup can poll the same canonical spool when `[spool]` is enabled in the daemon config:",
            "The current end-to-end MVP has two built-in correlation rules:",
        )

        for stale_claim in stale_claims:
            with self.subTest(stale_claim=stale_claim):
                document.write_text(current + f"\n{stale_claim}\n", encoding="utf-8")
                with self.assertRaises(SystemExit) as failure:
                    self.run_checker()
                self.assertIn("stale current-state claim", str(failure.exception))

    def test_rejects_duplicate_python_plugin_version_assignments(self) -> None:
        plugin = self.fixture_root / "integrations/hermes/skynet-edr/__init__.py"
        duplicate_assignments = (
            'PLUGIN_VERSION = "0.6.0-rc.1"',
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
            ("version", '"0.6.0-rc.1"'),
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
            ("version", "${SKYNET_EDR_DEB_VERSION:-0.6.0~rc.1}"),
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
                    self.assertIn("duplicate nFPM DEB default version", str(failure.exception))
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
        for duplicate_version in ("0.6.0-rc.1", "9.9.9"):
            with self.subTest(duplicate_version=duplicate_version):
                original = manifest.read_text(encoding="utf-8")
                manifest.write_text(
                    original.replace(
                        '"version": "0.6.0-rc.1",',
                        '"version": "0.6.0-rc.1",\n'
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
                        f'{dependency} = {{ version = "0.6.0-rc.1"',
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
            self.run_checker("--expected-product", "")

        self.assertIn("invalid release version", str(failure.exception))

    def test_accepts_prerelease_versions(self) -> None:
        for version in ("0.6.0-rc.1", "1.0.0-rc.1", "2.3.4"):
            with self.subTest(version=version):
                self.assertTrue(self.checker.is_canonical_release_version(version))

    def test_accepts_stable_current_repository_surfaces(self) -> None:
        result = subprocess.run(
            [
                "python3",
                str(CHECKER_PATH),
                "--expected-product",
                "0.6.0",
                "--expected-deb",
                "0.6.0",
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_checks_each_current_release_kind_authority_independently(self) -> None:
        cases = (
            (
                "docs/INSTALL.md",
                "Skynet-EDR is currently a pre-production, passive-first AI-agent Detection and Response project. The installable pre-1.0 stable SemVer evaluation release has a shipped live Hermes producer only; OpenClaw, Codex, Claude Code, and similar runtimes require an external conforming producer and are not shipped live integrations.",
                "Skynet-EDR is currently a pre-production, passive-first AI-agent Detection and Response project. The installable prerelease has a shipped live Hermes producer only; OpenClaw, Codex, Claude Code, and similar runtimes require an external conforming producer and are not shipped live integrations.",
                "docs/INSTALL.md misstates the stable current release kind",
            ),
            (
                "docs/README.md",
                "| Check what this pre-1.0 stable SemVer evaluation release actually supports | [MVP public support contract](MVP_SUPPORT_MATRIX.md) |",
                "| Check what this prerelease actually supports | [MVP public support contract](MVP_SUPPORT_MATRIX.md) |",
                "docs/README.md misstates the stable current release kind",
            ),
            (
                "docs/MVP_SUPPORT_MATRIX.md",
                "Skynet-EDR is a passive, local-first, Linux `x86_64`/`amd64` pre-1.0 stable SemVer evaluation release. It accepts and stores redacted local security evidence, applies bounded correlation, and exposes local read-only visibility. It detects and records; it does not block, pause, approve, quarantine, contain, or otherwise change an agent action.",
                "Skynet-EDR is a passive, local-first, Linux `x86_64`/`amd64` prerelease. It accepts and stores redacted local security evidence, applies bounded correlation, and exposes local read-only visibility. It detects and records; it does not block, pause, approve, quarantine, contain, or otherwise change an agent action.",
                "docs/MVP_SUPPORT_MATRIX.md misstates the stable current release kind",
            ),
            (
                "docs/MVP_SUPPORT_MATRIX.md",
                "Published checksums provide integrity checking, but this pre-1.0 stable SemVer evaluation release has no package signatures, signed checksum manifest, SBOM, provenance attestation, or bounded Hermes compatibility range.",
                "Published checksums provide integrity checking, but this prerelease has no package signatures, signed checksum manifest, SBOM, provenance attestation, or bounded Hermes compatibility range.",
                "docs/MVP_SUPPORT_MATRIX.md misstates the stable current release kind",
            ),
            (
                "docs/ROADMAP.md",
                "The release remains passive and is published as a pre-1.0 stable SemVer evaluation release. It has no production support commitment; signing, provenance, SBOM policy, broader platform validation, and repeatable runtime upgrade/rollback proof remain open. Release promotion is conditioned on the exact release SHA passing the disposable clean-host package/systemd, browser, and threat-validation gates. Autonomous Hermes enrollment remains unproven and blocked with the literal verdict `S3_ADAPTER_BLOCK`.",
                "The release remains passive and is published as a prerelease. It has no production support commitment; signing, provenance, SBOM policy, broader platform validation, and repeatable runtime upgrade/rollback proof remain open. Release promotion is conditioned on the exact release SHA passing the disposable clean-host package/systemd, browser, and threat-validation gates. Autonomous Hermes enrollment remains unproven and blocked with the literal verdict `S3_ADAPTER_BLOCK`.",
                "docs/ROADMAP.md misstates the stable current release kind",
            ),
        )
        authority_paths = {relative for relative, _, _, _ in cases}

        for relative, stable_literal, prerelease_literal, _ in cases:
            path = self.fixture_root / relative
            document = path.read_text(encoding="utf-8")
            self.assertEqual(document.count(prerelease_literal), 1)
            path.write_text(
                document.replace(prerelease_literal, stable_literal, 1),
                encoding="utf-8",
            )

        stable_baseline = {
            relative: (self.fixture_root / relative).read_text(encoding="utf-8")
            for relative in authority_paths
        }
        with mock.patch.object(self.checker, "ROOT", self.fixture_root):
            self.checker.require_current_release_kind("0.6.0")

        for relative, stable_literal, prerelease_literal, expected in cases:
            with self.subTest(relative=relative, stable_literal=stable_literal):
                for baseline_path, baseline_document in stable_baseline.items():
                    (self.fixture_root / baseline_path).write_text(
                        baseline_document,
                        encoding="utf-8",
                    )
                before = {
                    baseline_path: (self.fixture_root / baseline_path).read_text(
                        encoding="utf-8"
                    )
                    for baseline_path in authority_paths
                }
                path = self.fixture_root / relative
                self.assertEqual(before[relative].count(stable_literal), 1)
                path.write_text(
                    before[relative].replace(stable_literal, prerelease_literal, 1),
                    encoding="utf-8",
                )
                after = {
                    baseline_path: (self.fixture_root / baseline_path).read_text(
                        encoding="utf-8"
                    )
                    for baseline_path in authority_paths
                }
                changed_paths = {
                    baseline_path
                    for baseline_path in authority_paths
                    if before[baseline_path] != after[baseline_path]
                }
                self.assertEqual(changed_paths, {relative})

                with self.assertRaises(SystemExit) as failure:
                    with mock.patch.object(self.checker, "ROOT", self.fixture_root):
                        self.checker.require_current_release_kind("0.6.0")
                self.assertEqual(str(failure.exception), expected)

        for relative, baseline_document in stable_baseline.items():
            (self.fixture_root / relative).write_text(
                baseline_document,
                encoding="utf-8",
            )
        for relative, stable_literal, prerelease_literal, _ in cases:
            path = self.fixture_root / relative
            document = path.read_text(encoding="utf-8")
            self.assertEqual(document.count(stable_literal), 1)
            path.write_text(
                document.replace(stable_literal, prerelease_literal, 1),
                encoding="utf-8",
            )
        with mock.patch.object(self.checker, "ROOT", self.fixture_root):
            self.checker.require_current_release_kind("0.6.0-rc.1")

        for relative, baseline_document in stable_baseline.items():
            (self.fixture_root / relative).write_text(
                baseline_document,
                encoding="utf-8",
            )
        historical = self.fixture_root / "docs/INSTALL.md"
        historical.write_text(
            historical.read_text(encoding="utf-8")
            + "\nHistorical release v0.5.0 was a prerelease.\n",
            encoding="utf-8",
        )
        generic = self.fixture_root / "docs/ROADMAP.md"
        generic.write_text(
            generic.read_text(encoding="utf-8")
            + "\nFuture prerelease validation remains required.\n",
            encoding="utf-8",
        )
        with mock.patch.object(self.checker, "ROOT", self.fixture_root):
            self.checker.require_current_release_kind("0.6.0")

    def test_maps_stable_and_prerelease_products_to_exact_native_versions(self) -> None:
        for product, native in (
            ("0.6.0", "0.6.0"),
            ("0.6.0-rc.1", "0.6.0~rc.1"),
        ):
            with self.subTest(product=product):
                self.assertEqual(self.checker.native_package_version(product), native)

    def test_rejects_native_version_that_inverts_release_kind(self) -> None:
        stable_result = subprocess.run(
            [
                sys.executable,
                str(CHECKER_PATH),
                "--expected-product",
                "0.6.0",
                "--expected-deb",
                "0.6.0~rc.1",
            ],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(stable_result.returncode, 0)
        self.assertIn("invalid Debian package version", stable_result.stderr)

        with self.assertRaises(SystemExit) as prerelease_failure:
            self.run_checker(
                "--expected-product",
                "0.6.0-rc.1",
                "--expected-deb",
                "0.6.0",
            )
        self.assertIn("invalid Debian package version", str(prerelease_failure.exception))

    def test_rejects_malformed_or_noncanonical_semver_prerelease(self) -> None:
        for version in (
            "",
            "v0.6.0-rc.1",
            "01.6.0-alpha.1",
            "0.06.0-alpha.1",
            "0.6.00-alpha.1",
            "0.6.0-",
            "0.6.0-alpha..1",
            "0.6.0-alpha.01",
            "0.6.0+build.1",
            "0.6.0-rc.1+build.1",
        ):
            with self.subTest(version=version):
                self.assertFalse(self.checker.is_canonical_release_version(version))

    def test_rejects_stale_authoritative_current_version_docs(self) -> None:
        for relative, current_marker in (
            ("SECURITY.md", "Skynet-EDR v0.6.0-rc.1 is an installable prerelease"),
            ("SECURITY.md", "| `v0.6.0-rc.1` prerelease |"),
            ("docs/README.md", "Current documentation structure target: v0.6.0-rc.1."),
        ):
            with self.subTest(relative=relative):
                path = self.fixture_root / relative
                original = path.read_text(encoding="utf-8")
                path.write_text(
                    original.replace(current_marker, current_marker.replace("0.6.0-rc.1", "9.9.9")),
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn(
                        f"{relative} does not reference current release 0.6.0-rc.1",
                        str(failure.exception),
                    )
                finally:
                    path.write_text(original, encoding="utf-8")

    def test_rejects_stale_current_product_surface_versions(self) -> None:
        for relative, current_marker in (
            ("docs/ARCHITECTURE.md", "ships in v0.6.0-rc.1"),
            ("docs/CONCEPTS.md", "## Current v0.6.0-rc.1 scope"),
            ("docs/HERMES_PLUGIN_TELEMETRY.md", "Skynet-EDR v0.6.0-rc.1 ships"),
            ("docs/INTEGRATIONS.md", "the v0.6.0-rc.1 integration index"),
            ("docs/INTEGRATIONS.md", "v0.6.0-rc.1 live passive path"),
            ("docs/OPERATIONS.md", "the v0.6.0-rc.1 operator index"),
            (
                "integrations/hermes/skynet-edr/README.md",
                "Skynet-EDR v0.6.0-rc.1.",
            ),
            (
                "integrations/hermes/skynet-edr/README.md",
                "No inline blocking in v0.6.0-rc.1.",
            ),
        ):
            with self.subTest(relative=relative, marker=current_marker):
                path = self.fixture_root / relative
                original = path.read_text(encoding="utf-8")
                self.assertIn(current_marker, original)
                path.write_text(
                    original.replace(
                        current_marker,
                        current_marker.replace("0.6.0-rc.1", "9.9.9"),
                    ),
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn(
                        f"{relative} does not reference current release 0.6.0-rc.1",
                        str(failure.exception),
                    )
                finally:
                    path.write_text(original, encoding="utf-8")

    def test_rejects_stale_install_enrollment_and_enroller_versions(self) -> None:
        cases = (
            ("docs/INSTALL.md", "DEB and RPM report `0.6.0~rc.1`", "DEB and RPM report `9.9.9`"),
            ("docs/INSTALL.md", "Arch reports `0.6.0.rc.1-1`", "Arch reports `9.9.9-1`"),
            ("docs/HERMES_ENROLLMENT.md", "Skynet-EDR plugin `0.6.0-rc.1`", "Skynet-EDR plugin `9.9.9`"),
            ("packaging/scripts/skynet-edr-hermes-enroll.py", 'PAYLOAD_VERSION = "0.6.0-rc.1"', 'PAYLOAD_VERSION = "9.9.9"'),
        )
        for relative, marker, stale in cases:
            with self.subTest(relative=relative, marker=marker):
                path = self.fixture_root / relative
                original = path.read_text(encoding="utf-8")
                path.write_text(original.replace(marker, stale), encoding="utf-8")
                try:
                    with self.assertRaises(SystemExit):
                        self.run_checker()
                finally:
                    path.write_text(original, encoding="utf-8")

    def test_rejects_contradictory_authoritative_current_version_docs(self) -> None:
        cases = (
            (
                "SECURITY.md",
                "\nSkynet-EDR v9.9.9 is an installable prerelease for evaluation.\n",
            ),
            (
                "SECURITY.md",
                "\n| `v9.9.9` prerelease | Best effort | Contradictory row |\n",
            ),
            (
                "docs/README.md",
                "\nCurrent documentation structure target: v9.9.9.\n",
            ),
        )
        for relative, contradiction in cases:
            with self.subTest(relative=relative, contradiction=contradiction):
                path = self.fixture_root / relative
                original = path.read_text(encoding="utf-8")
                path.write_text(original + contradiction, encoding="utf-8")
                try:
                    with self.assertRaises(SystemExit) as failure:
                        self.run_checker()
                    self.assertIn(
                        f"{relative} does not reference current release 0.6.0-rc.1",
                        str(failure.exception),
                    )
                finally:
                    path.write_text(original, encoding="utf-8")

    def test_rejects_reordered_internal_dependency_version(self) -> None:
        daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
        daemon_manifest.write_text(
            daemon_manifest.read_text(encoding="utf-8").replace(
                'skynet-edr-core = { version = "0.6.0-rc.1", path = "../skynet-edr-core" }',
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
                'skynet-edr-core = { version = "0.6.0-rc.1", path = "../skynet-edr-core" }',
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
                'skynet-edr-core = { version = "0.6.0-rc.1", path = "../skynet-edr-core" }',
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
                'skynet-edr-core = { path = "crates/skynet-edr-core", version = ">=0.6.0-rc.1" }\n'
            )
        source_directory = self.fixture_root / "src"
        source_directory.mkdir()
        (source_directory / "lib.rs").write_text("", encoding="utf-8")
        self.refresh_lock()

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn("skynet-edr-root dependencies skynet-edr-core=>=0.6.0-rc.1", str(failure.exception))

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
            'skynet-edr-core = { path = "../skynet-edr-core", version = ">=0.6.0-rc.1" }\n',
            encoding="utf-8",
        )
        daemon_manifest = self.fixture_root / "crates/skynet-edr-daemon/Cargo.toml"
        daemon_manifest.write_text(
            daemon_manifest.read_text(encoding="utf-8").replace(
                "[dev-dependencies]\n",
                "[dev-dependencies]\n"
                'skynet-edr-implicit = { path = "../skynet-edr-implicit", version = "0.6.0-rc.1" }\n',
            ),
            encoding="utf-8",
        )
        self.refresh_lock()

        with self.assertRaises(SystemExit) as failure:
            self.run_checker()

        self.assertIn(
            "skynet-edr-implicit dependencies skynet-edr-core=>=0.6.0-rc.1",
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
                'skynet-edr-core = { version = "0.6.0-rc.1", path = "../skynet-edr-core" }',
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
        current_entry = '[[package]]\nname = "skynet-edr-core"\nversion = "0.6.0-rc.1"'
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
