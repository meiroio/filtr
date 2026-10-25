import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deploy/simple"))
import apache
from common import InstallError
import inventory
import main
from transaction import Transaction


class DiscoveryTests(unittest.TestCase):
    def test_dpkg_keeps_epoch_distribution_architecture_and_vendor_build(self):
        output = "php8.2:amd64\t2:8.2.35-1+deb12u1\tamd64\tphp8.2\t2:8.2.35-1+deb12u1\tinstalled\nremoved\t1\tall\tremoved\t1\tconfig-files\n"
        found = inventory.deb_components(output, ("debian", "12"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["version"], "2:8.2.35-1+deb12u1")
        self.assertIn("2%3A8.2.35-1%2Bdeb12u1", found[0]["purl"])
        self.assertIn("distro=debian-12", found[0]["purl"])
        self.assertIn("arch=amd64", found[0]["purl"])

    def test_composer_reads_installed_versions_and_does_not_execute_project_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "vendor/composer").mkdir(parents=True)
            (root / "composer.lock").write_text('{"packages":[{"name":"vendor/pkg","version":"9.9.9"}]}')
            found, missing = inventory.composer_components(root)
            self.assertFalse(found)
            self.assertEqual(len(missing), 1)
            (root / "vendor/composer/installed.json").write_text(json.dumps({"packages": [
                {"name": "vendor/pkg", "version": "1.0.0"},
                {"name": "vendor/dev", "version": "dev-main"}]}))
            found, missing = inventory.composer_components(root)
            self.assertEqual(found[0]["purl"], "pkg:composer/vendor/pkg@1.0.0")
            self.assertEqual(len(missing), 1)

    def test_wordpress_metadata_reports_missing_and_bundled_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "wp-includes").mkdir()
            (root / "wp-includes/version.php").write_text("<?php $wp_version = '6.9.1';")
            plugin = root / "wp-content/plugins/example"
            plugin.mkdir(parents=True)
            (plugin / "example.php").write_text("<?php /*\nPlugin Name: Example\nVersion: 1.2.3\n*/")
            found, missing = inventory.wordpress_components(root)
            self.assertEqual(len(found), 2)
            self.assertEqual(found[1]["version"], "1.2.3")
            self.assertTrue(any("bundled" in c["name"] for c in missing))

    def test_application_symlinks_cannot_read_external_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "app"
            (root / "vendor/composer").mkdir(parents=True)
            external = base / "private.json"
            external.write_text('{"packages":[{"name":"private/secret","version":"1.0.0"}]}')
            (root / "vendor/composer/installed.json").symlink_to(external)
            found, missing = inventory.composer_components(root)
            self.assertFalse(found)
            self.assertTrue(missing)
            self.assertNotIn("private/secret", json.dumps(missing))

    def test_environment_file_is_data_and_never_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys"
            path.write_text("ANTHROPIC_API_KEY='$(touch /tmp/filtr-must-not-execute)'\nFILTR_AI_MODEL='chosen-model'\n")
            path.chmod(0o600)
            values = main.optional_env(path)
            self.assertTrue(values["ANTHROPIC_API_KEY"].startswith("$("))
            self.assertEqual(values["FILTR_AI_MODEL"], "chosen-model")
            path.write_text("FILTR_UPSTREAM=http://attacker\n")
            with self.assertRaises(InstallError):
                main.optional_env(path)


class ApacheTests(unittest.TestCase):
    def test_certbot_redirect_becomes_unconditional_and_contains_no_php_handler(self):
        block = apache.Vhost("*:80", ["ServerName example.com", "DocumentRoot /var/www/html",
            "RewriteEngine on", "RewriteCond %{SERVER_NAME} =example.com",
            "RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]"], Path("site"))
        self.assertTrue(apache.redirect_only(block, "example.com"))
        result = apache.redirect_frontend(block)
        self.assertIn("Redirect permanent / https://example.com/", result)
        self.assertNotIn("DocumentRoot", result)
        self.assertNotIn("RewriteCond", result)

    def test_profile_keeps_certificates_public_and_php_backend_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = root / "apache"
            (config / "sites-available").mkdir(parents=True)
            (config / "sites-enabled").mkdir()
            site = config / "sites-available/site.conf"
            site.write_text(f'''<IfModule mod_ssl.c>
<VirtualHost *:443>
ServerName example.com
DocumentRoot "{root}"
SSLEngine on
SSLCertificateFile /cert.pem
<Directory "{root}">
Require all granted
</Directory>
</VirtualHost>
</IfModule>
''')
            (config / "sites-enabled/site.conf").symlink_to(site)
            plan = apache.plan("example.com", 8080, 8081, config)
            frontend = plan["changes"][site].decode()
            backend = plan["changes"][config / "conf-enabled/filtr-simple-backend.conf"].decode()
            self.assertIn("SSLCertificateFile /cert.pem", frontend)
            self.assertNotIn("DocumentRoot", frontend)
            self.assertIn("127.0.0.1:8081", backend)
            self.assertNotIn("SSLEngine", backend)
            self.assertIn("HTTPS=on", backend)
            self.assertIn('RequestHeader unset X-Forwarded-Proto', frontend)

    def test_complex_config_and_unsafe_https_redirects_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for directive in ["ProxyPass / http://elsewhere/", "RewriteRule ^ /index.php [L]",
                              "Include /another/application.conf", "SSLVerifyClient require", "SSLRequireSSL"]:
                block = apache.Vhost("*:80", [f'DocumentRoot "{root}"', directive], root / "site")
                with self.assertRaises(InstallError):
                    apache.check_application(block)
            (root / ".htaccess").write_text("RewriteCond %{HTTPS} off\n")
            block = apache.Vhost("*:443", [f'DocumentRoot "{root}"'], root / "site")
            with self.assertRaises(InstallError):
                apache.check_application(block)


@unittest.skipUnless(os.geteuid() == 0, "transaction owner/mode tests run in the Linux root fixture")
class TransactionTests(unittest.TestCase):
    def test_before_images_restore_bytes_modes_symlinks_and_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original, link, added = [root / n for n in ("original", "link", "added")]
            original.write_text("before")
            original.chmod(0o640)
            link.symlink_to("original")
            transaction = Transaction(root / "state")
            (root / "state").mkdir()
            transaction.begin([original, link, added], {})
            original.write_text("after")
            link.unlink()
            link.symlink_to("elsewhere")
            added.write_text("new")
            transaction.finish()
            transaction.restore_files()
            self.assertEqual(original.read_text(), "before")
            self.assertEqual(original.stat().st_mode & 0o777, 0o640)
            self.assertEqual(os.readlink(link), "original")
            self.assertFalse(added.exists())

    def test_rollback_refuses_to_overwrite_later_operator_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "site"
            path.write_text("before")
            (root / "state").mkdir()
            transaction = Transaction(root / "state")
            transaction.begin([path], {})
            path.write_text("installed")
            transaction.finish()
            path.write_text("operator edit")
            with self.assertRaises(InstallError):
                transaction.restore_files()
            self.assertEqual(path.read_text(), "operator edit")


if __name__ == "__main__":
    unittest.main()
