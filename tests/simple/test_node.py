import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock
import ipaddress

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deploy/simple"))
from common import InstallError
import nginx
import node_inventory
import node_runtime
import apache
import service


def npm_package(path, name, version):
    path.mkdir(parents=True, exist_ok=True)
    (path / "package.json").write_text(json.dumps({"name": name, "version": version,
                                                "scripts": {"install": "must never run"}}))


class NodeInventoryTests(unittest.TestCase):
    def test_actual_installed_tree_keeps_nested_versions_scopes_and_workspace_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            modules = root / "node_modules"
            npm_package(modules / "express", "express", "5.1.0")
            npm_package(modules / "@scope/pkg", "@scope/pkg", "1.2.3")
            npm_package(modules / "express/node_modules/nested", "nested", "1.0.0")
            npm_package(modules / "nested", "nested", "2.0.0")
            npm_package(root / "packages/local", "local", "0.1.0")
            (modules / "local").symlink_to(root / "packages/local")
            found, gaps = node_inventory.installed(root)
            identities = {p["purl"] for p in found}
            self.assertIn("pkg:npm/%40scope/pkg@1.2.3", identities)
            self.assertIn("pkg:npm/nested@1.0.0", identities)
            self.assertIn("pkg:npm/nested@2.0.0", identities)
            self.assertIn("pkg:npm/local@0.1.0", identities)
            self.assertFalse(gaps)

    def test_pnpm_store_and_external_symlinks_are_handled_without_loading_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "app"
            modules = root / "node_modules"
            store = modules / ".pnpm/express@5.1.0/node_modules/express"
            npm_package(store, "express", "5.1.0")
            (modules / "express").symlink_to(store)
            npm_package(base / "outside", "secret", "1.0.0")
            (modules / "external").symlink_to(base / "outside")
            found, gaps = node_inventory.installed(root)
            self.assertEqual([p["name"] for p in found], ["express"])
            self.assertTrue(gaps)
            self.assertNotIn("secret", json.dumps(found + gaps))

    def test_lockfile_without_deployed_modules_never_becomes_an_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "package-lock.json").write_text('{"packages":{"node_modules/express":{"version":"5.1.0"}}}')
            found, gaps = node_inventory.installed(root)
            self.assertFalse(found)
            self.assertIn("lockfiles", gaps[0]["properties"][0]["value"])

    def test_backend_must_be_owned_by_node_and_private(self):
        loopback = ipaddress.ip_address("127.0.0.1")
        port, origin = node_runtime.private_endpoint([(loopback, 3000)])
        self.assertEqual((port, origin), (3000, "http://127.0.0.1:3000"))
        for bindings in [[(ipaddress.ip_address("0.0.0.0"), 3000)], [(loopback, 3000), (loopback, 9229)]]:
            with self.assertRaises(InstallError):
                node_runtime.private_endpoint(bindings)
        with self.assertRaises(InstallError):
            node_runtime.private_endpoint([(loopback, 3000)], 4000)

    def test_runtime_uses_matching_distribution_build_without_losing_backports(self):
        runtime = {"executable": "/usr/bin/node", "versions": {"node": "18.20.8"}}
        host = [{"name": "nodejs", "version": "18.20.8+dfsg-1~deb12u1"}]
        with mock.patch.object(node_inventory, "run", return_value="nodejs: /usr/bin/node\n"):
            self.assertEqual(node_inventory.runtime_component(runtime, host), ([], []))

    def test_replaced_or_mismatched_runtime_is_reported_as_observed_build_gap(self):
        runtime = {"executable": "/usr/bin/node (deleted)", "versions": {"node": "18.20.7"}}
        with mock.patch.object(node_inventory, "run") as query:
            components, gaps = node_inventory.runtime_component(runtime, [])
            query.assert_not_called()
        self.assertEqual(components[0]["version"], "18.20.7")
        self.assertTrue(gaps)


class NginxTests(unittest.TestCase):
    def test_worker_snapshot_tolerates_a_process_exit_during_read(self):
        with mock.patch.object(service, "read", side_effect=[b"100", b"101"]), \
                mock.patch.object(service.Path, "open", side_effect=ProcessLookupError):
            self.assertEqual(service.nginx_workers(), set())

    def test_reload_waits_until_old_workers_stop_accepting_before_returning(self):
        with mock.patch.object(service, "nginx_workers", side_effect=[{101}, {101, 102}, {102}]) as workers, \
                mock.patch.object(service, "run") as run, mock.patch.object(service.time, "sleep"):
            service.reload_web_server("nginx")
            self.assertEqual(workers.call_count, 3)
            run.assert_called_once_with(["systemctl", "reload", "nginx"])

    def test_root_proxy_preserves_tls_custom_headers_and_normalizes_forwarding(self):
        text = '''server {
listen 443 ssl;
server_name example.com;
ssl_certificate /cert.pem;
ssl_certificate_key /key.pem;
proxy_set_header X-Custom "private value";
location / {
proxy_pass http://127.0.0.1:3000;
}
}
'''
        server = nginx.parse(text)[0]
        for start, end, replacement in sorted(nginx.route_edits(server, text, 8080, 3000), reverse=True):
            text = text[:start] + replacement + text[end:]
        parsed = nginx.parse(text)[0]
        location = parsed.named("location")[0]
        self.assertEqual(location.named("proxy_pass")[0].args, ["http://127.0.0.1:8080"])
        self.assertEqual(parsed.named("ssl_certificate")[0].args, ["/cert.pem"])
        self.assertIn(["X-Custom", "private value"], [d.args for d in location.named("proxy_set_header")])
        self.assertIn(["X-Forwarded-For", "$remote_addr"], [d.args for d in location.named("proxy_set_header")])
        self.assertNotIn("$proxy_add_x_forwarded_for", text)

    def test_split_locations_dynamic_upstreams_and_websockets_require_manual_integration(self):
        for fragment in ["location / {proxy_pass http://backend;} ",
                         "location / {proxy_pass http://127.0.0.1:3000; proxy_set_header Upgrade $http_upgrade;}",
                         "location / {proxy_pass http://127.0.0.1:3000;} location /api {proxy_pass http://127.0.0.1:3000;}"]:
            text = "server {listen 80; server_name example.com; " + fragment + "}"
            with self.assertRaises(InstallError):
                nginx.route_edits(nginx.parse(text)[0], text, 8080, 3000)

    def test_apache_node_profile_reuses_fixed_origin_frontend(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "sites-available").mkdir()
            (root / "sites-enabled").mkdir()
            site = root / "sites-available/node.conf"
            site.write_text('''<VirtualHost *:80>
ServerName example.com
ProxyPreserveHost On
ProxyPass / http://127.0.0.1:3000/
ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>
''')
            (root / "sites-enabled/node.conf").symlink_to(site)
            result = apache.node_plan("example.com", 8080, 3000, root)
            self.assertEqual(result["web_server"], "apache")
            self.assertIn(b"127.0.0.1:8080/", result["changes"][site])
            self.assertNotIn(root / "conf-enabled/filtr-simple-backend.conf", result["changes"])


if __name__ == "__main__":
    unittest.main()
