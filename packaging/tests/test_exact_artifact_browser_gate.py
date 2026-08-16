from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "packaging" / "scripts" / "exact-artifact-browser-gate.sh"
BROWSER = ROOT / "packaging" / "scripts" / "hermes-browser-smoke.mjs"
BROWSER_LOCK = ROOT / "packaging" / "browser-gate" / "package-lock.json"
DEGRADED_FIXTURE = ROOT / "crates" / "skynet-edr-daemon" / "tests" / "fixtures" / "status_alert_delivery_degraded.json"
WORKFLOWS = (
    ROOT / ".github" / "workflows" / "packaging-release.yml",
    ROOT / ".github" / "workflows" / "release-artifacts.yml",
)
PIN = "f5be9236e00ddf2f2a412697f267078fc4ee068e"


class ExactArtifactBrowserGateTests(unittest.TestCase):
    def test_real_hermes_enable_is_pinned_noninteractive_and_route_is_proven(self) -> None:
        text = GATE.read_text(encoding="utf-8")
        self.assertIn(f"HERMES_REF={PIN}", text)
        self.assertIn("plugins enable --no-allow-tool-override skynet-edr", text)
        self.assertIn("/api/plugins/skynet-edr/status", text)
        self.assertIn("X-Hermes-Session-Token", text)
        self.assertIn("unauthenticated plugin proxy did not fail closed", text)
        self.assertNotIn("--hermes-ref", text)

    def test_gate_starts_service_runs_root_verifier_and_checks_user_copy_policy(self) -> None:
        text = GATE.read_text(encoding="utf-8")
        self.assertIn('deb=$(realpath -- "$deb")', text)
        self.assertLess(
            text.index('deb=$(realpath -- "$deb")'),
            text.index('sudo dpkg --install "$deb"'),
        )
        self.assertIn('[[ "$(dpkg-deb -f "$deb" Depends)" == "systemd, python3" ]]', text)
        self.assertIn("for dependency in systemd python3", text)
        self.assertIn("'${db:Status-Abbrev}'", text)
        self.assertNotIn("apt-get install", text)
        self.assertIn('[[ -n "${PLAYWRIGHT_BROWSERS_PATH:-}"', text)
        self.assertIn("chromium.executablePath()", text)
        self.assertLess(text.index("systemctl start skynet-edr.service"), text.index("sudo /usr/libexec/skynet-edr/deploy-verify"))
        self.assertIn('--hermes-plugin-uid "$(id -u)"', text)
        self.assertIn('--hermes-plugin-gid "$(id -g)"', text)
        self.assertIn("browser degraded-lane fixture version mismatch", text)

    def test_degraded_lane_fixture_tracks_release_version(self) -> None:
        fixture = DEGRADED_FIXTURE.read_text(encoding="utf-8")
        self.assertIn('"version": "0.7.0-alpha.2"', fixture)
        self.assertNotIn('"version": "0.6.0"', fixture)

    def test_loaded_user_copy_remains_exact_and_package_integrity_is_rechecked(self) -> None:
        text = GATE.read_text(encoding="utf-8")
        bytecode = text.index("export PYTHONDONTWRITEBYTECODE=1")
        hermes_command_lines = [
            line for line in text.splitlines() if line.lstrip().startswith('"$hermes_cli"')
        ]
        self.assertEqual(len(hermes_command_lines), 2)
        hermes_invocations = [text.index(line) for line in hermes_command_lines]
        self.assertTrue(all(bytecode < invocation for invocation in hermes_invocations))

        verifier_calls = []
        cursor = 0
        marker = "\nverify_installed_payloads\n"
        while True:
            cursor = text.find(marker, cursor)
            if cursor < 0:
                break
            verifier_calls.append(cursor)
            cursor += len(marker)
        self.assertEqual(len(verifier_calls), 3)

        enable = text.index('"$hermes_cli" plugins enable')
        dashboard = text.index('"$hermes_cli" dashboard')
        normal = text.index('"http://127.0.0.1:${HERMES_PORT}/skynet-edr/risks" normal')
        first_stop = text.index("sudo systemctl stop skynet-edr.service", normal)
        degraded = text.index('"http://127.0.0.1:${HERMES_PORT}/skynet-edr/risks" alert-delivery')
        fixture_kill = text.index('kill "$fixture_pid"', degraded)
        fixture_wait = text.index('wait "$fixture_pid"', fixture_kill)
        fixture_clear = text.index('fixture_pid=""', fixture_wait)
        real_restart = text.index("sudo systemctl start skynet-edr.service", fixture_clear)
        service_mark = text.index("service_started=1", real_restart)
        final_ready = text.index(
            'done\ncurl --fail --silent "http://127.0.0.1:${DAEMON_PORT}/api/status" >/dev/null',
            service_mark,
        )
        final_package_check = text.index("dpkg -V skynet-edr", verifier_calls[2])
        final_checksum = text.rindex('sha256sum "$deb"')

        self.assertLess(enable, verifier_calls[0])
        self.assertLess(verifier_calls[0], dashboard)
        self.assertLess(normal, verifier_calls[1])
        self.assertLess(verifier_calls[1], first_stop)
        self.assertLess(degraded, fixture_kill)
        self.assertLess(fixture_kill, fixture_wait)
        self.assertLess(fixture_wait, fixture_clear)
        self.assertLess(fixture_clear, real_restart)
        self.assertLess(real_restart, service_mark)
        self.assertLess(service_mark, final_ready)
        self.assertLess(final_ready, verifier_calls[2])
        self.assertLess(verifier_calls[2], final_package_check)
        self.assertLess(final_package_check, final_checksum)

    def test_browser_uses_only_authenticated_same_origin_proxy(self) -> None:
        browser = BROWSER.read_text(encoding="utf-8")
        self.assertNotIn("localeCompare", browser)
        self.assertIn("a < b ? -1 : a > b ? 1 : 0", browser)
        self.assertIn("headless: true", browser)
        self.assertIn("0.7.0-alpha.2", browser)
        self.assertIn("Engine Online", browser)
        self.assertIn("Backend available", browser)
        self.assertIn("Telemetry degraded", browser)
        self.assertIn("request.url().includes(':8787')", browser)
        self.assertNotIn("http://127.0.0.1:8787", browser)
        self.assertIn("process.env.HERMES_DASHBOARD_SESSION_TOKEN", browser)
        self.assertIn("sessionToken.length < 32", browser)
        self.assertIn("sessionToken.length > 256", browser)
        self.assertNotIn("extraHTTPHeaders", browser)
        self.assertIn("serviceWorkers: 'block'", browser)
        self.assertIn("installAuthenticatedOriginProxy(context, url, sessionToken, failures)", browser)
        self.assertIn("const page = await context.newPage()", browser)
        self.assertIn("await context.close()", browser)

        proxy = (ROOT / "packaging/scripts/hermes-browser-origin-proxy.mjs").read_text(encoding="utf-8")
        self.assertIn("context.route('**/*'", proxy)
        self.assertIn("requestUrl.origin !== targetOrigin", proxy)
        self.assertIn("maxRedirects: 0", proxy)
        self.assertIn("blocked authenticated redirect", proxy)
        self.assertNotIn("route.continue", proxy)
        self.assertIn("test-hermes-browser-origin-proxy.mjs", GATE.read_text(encoding="utf-8"))

    def test_both_workflows_gate_one_deb_before_upload_or_publication(self) -> None:
        gate = GATE.read_text(encoding="utf-8")
        self.assertIn('"http://127.0.0.1:${HERMES_PORT}/skynet-edr/risks" normal', gate)
        self.assertIn('"http://127.0.0.1:${HERMES_PORT}/skynet-edr/risks" alert-delivery', gate)
        for workflow in WORKFLOWS:
            text = workflow.read_text(encoding="utf-8")
            self.assertIn("PLAYWRIGHT_BROWSERS_PATH: /tmp/skynet-edr-ms-playwright", text)
            with self.subTest(workflow=workflow.name):
                self.assertIn("https://github.com/NousResearch/hermes-agent.git", text)
                self.assertIn(PIN, text)
                self.assertIn("af5c1d6d97095438138cb50a3beb5ed7cd8f75f775283db7b43d9a027e869a6e", text)
                self.assertLess(text.index("Verify accepted reproducible DEB identity"), text.index("exact-artifact-browser-gate.sh"))
                self.assertLess(text.index("Prepare frozen Hermes and browser dependencies before artifact build"), text.index("packaging/scripts/build-tarball.sh"))
                self.assertGreaterEqual(text.count("sha256sum -c checksums.txt"), 5)
                self.assertLess(text.index("exact-artifact-browser-gate.sh"), text.index("actions/upload-artifact@"))
        release = WORKFLOWS[0].read_text(encoding="utf-8")
        self.assertLess(release.index("exact-artifact-browser-gate.sh"), release.index("gh release create"))

    def test_gate_has_no_post_build_dependency_install_and_browser_lock_is_frozen(self) -> None:
        gate = GATE.read_text(encoding="utf-8")
        self.assertNotIn("pip install", gate)
        self.assertNotIn("npm install", gate)
        self.assertNotIn("playwright install", gate)
        lock = BROWSER_LOCK.read_text(encoding="utf-8")
        self.assertIn('"playwright": "1.62.1"', lock)
        self.assertIn('"integrity": "sha512-', lock)

    def test_manual_execution_is_rejected_before_argument_validation(self) -> None:
        result = subprocess.run(
            [str(GATE)], cwd=ROOT, env={"PATH": "/usr/bin:/bin"},
            check=False, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GITHUB_ACTIONS=true", result.stderr)


if __name__ == "__main__":
    unittest.main()