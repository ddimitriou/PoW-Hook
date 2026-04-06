import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import json

class TestPOWHooks(unittest.TestCase):
    def setUp(self):
        self.original_cwd = os.getcwd()
        self.temp_dir = tempfile.mkdtemp()
        os.chdir(self.temp_dir)

        # Mock HOME so keys are generated in temp dir
        self.original_home = os.environ.get("HOME", "")
        os.environ["HOME"] = self.temp_dir

        # Init git repo
        subprocess.check_call(["git", "init"])
        subprocess.check_call(["git", "config", "user.name", "Test User"])
        subprocess.check_call(["git", "config", "user.email", "test@example.com"])

        # Copy the templates and setup scripts from the original repo
        shutil.copytree(os.path.join(self.original_cwd, "hooks_templates"), "hooks_templates")
        shutil.copytree(os.path.join(self.original_cwd, "admin_templates"), "admin_templates")
        shutil.copy2(os.path.join(self.original_cwd, "setup_hooks.py"), "setup_hooks.py")
        shutil.copy2(os.path.join(self.original_cwd, "install.sh"), "install.sh")
        shutil.copy2(os.path.join(self.original_cwd, ".env.example"), ".env.example")

        # Create a test .env file (no PAT — attestation dispatch will be skipped)
        with open(".env", "w") as f:
            f.write("# Empty env\n")

        # Run install.sh to generate keys and install hooks
        os.chmod("install.sh", 0o755)
        subprocess.check_call(["./install.sh"])

        # Load the generated public key to populate POW_PUBLIC_KEYS
        with open(os.path.join(self.temp_dir, ".pow", "public_key.pem"), "r") as f:
            pub_key = f.read()

        os.environ["POW_PUBLIC_KEYS"] = json.dumps({"test_user": pub_key})

    def tearDown(self):
        os.chdir(self.original_cwd)
        os.environ["HOME"] = self.original_home
        if "POW_PUBLIC_KEYS" in os.environ:
            del os.environ["POW_PUBLIC_KEYS"]
        shutil.rmtree(self.temp_dir)

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    def _get_trailer(self, key):
        """Extract a specific trailer value from the latest commit."""
        return subprocess.check_output([
            "git", "log", "-1",
            f"--format=%(trailers:key={key},valueonly)"
        ]).decode().strip()

    # -----------------------------------------------------------------
    # Tests
    # -----------------------------------------------------------------

    def test_commit_flow_generates_trifactor_trailers(self):
        """A normal commit should produce all three trailers."""
        with open("test_file.txt", "w") as f:
            f.write("Hello world!")
        subprocess.check_call(["git", "add", "test_file.txt"])
        subprocess.check_call(["git", "commit", "-m", "Initial commit"])

        self.assertTrue(self._get_trailer("Validated-At-Local"))
        self.assertTrue(self._get_trailer("PoW-Session"))
        self.assertTrue(self._get_trailer("PoW-Status"))
        self.assertEqual(self._get_trailer("PoW-Status"), "PASSED")

    def test_merge_flow_generates_trifactor_trailers(self):
        """A --no-ff merge should also carry tri-factor trailers."""
        with open("test_file.txt", "w") as f:
            f.write("Initial")
        subprocess.check_call(["git", "add", "test_file.txt"])
        subprocess.check_call(["git", "commit", "-m", "Initial commit"])

        subprocess.check_call(["git", "checkout", "-b", "feature"])
        with open("feature.txt", "w") as f:
            f.write("Feature")
        subprocess.check_call(["git", "add", "feature.txt"])
        subprocess.check_call(["git", "commit", "-m", "Feature commit"])

        subprocess.check_call(["git", "checkout", "main"])
        subprocess.check_call(["git", "merge", "--no-ff", "feature", "-m", "Merge feature"])

        self.assertTrue(self._get_trailer("Validated-At-Local"))
        self.assertTrue(self._get_trailer("PoW-Session"))
        self.assertEqual(self._get_trailer("PoW-Status"), "PASSED")

    def test_pre_receive_rejects_missing_trailers(self):
        """pre-receive must reject commits created with --no-verify."""
        with open("valid.txt", "w") as f:
            f.write("Valid")
        subprocess.check_call(["git", "add", "valid.txt"])
        subprocess.check_call(["git", "commit", "-m", "Valid commit"])
        valid_commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

        with open("invalid.txt", "w") as f:
            f.write("Invalid")
        subprocess.check_call(["git", "add", "invalid.txt"])
        subprocess.check_call(["git", "commit", "--no-verify", "-m", "Invalid commit"])
        invalid_commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

        pre_receive_path = "admin_templates/pre-receive_hook/pre-receive"
        os.chmod(pre_receive_path, 0o755)

        stdin_data = f"{valid_commit} {invalid_commit} refs/heads/main\n".encode()
        process = subprocess.Popen(
            [sys.executable, pre_receive_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = process.communicate(input=stdin_data)

        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"REJECTED", stdout)

    def test_pre_receive_accepts_valid_trifactor(self):
        """pre-receive must accept commits with valid tri-factor signatures."""
        with open("valid1.txt", "w") as f:
            f.write("Valid1")
        subprocess.check_call(["git", "add", "valid1.txt"])
        subprocess.check_call(["git", "commit", "-m", "Valid 1"])
        old = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

        with open("valid2.txt", "w") as f:
            f.write("Valid2")
        subprocess.check_call(["git", "add", "valid2.txt"])
        subprocess.check_call(["git", "commit", "-m", "Valid 2"])
        new = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

        pre_receive_path = "admin_templates/pre-receive_hook/pre-receive"
        os.chmod(pre_receive_path, 0o755)

        stdin_data = f"{old} {new} refs/heads/main\n".encode()
        process = subprocess.Popen(
            [sys.executable, pre_receive_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = process.communicate(input=stdin_data)
        self.assertEqual(process.returncode, 0)

    def test_custom_checks_pass_and_fail(self):
        """POW_CHECKS_CMD success produces trailers; failure aborts commit."""
        with open("custom_hook.sh", "w") as f:
            f.write("#!/bin/bash\nexit 0\n")
        os.chmod("custom_hook.sh", 0o755)

        with open(".env", "a") as f:
            f.write('POW_CHECKS_CMD="./custom_hook.sh"\n')

        with open("valid3.txt", "w") as f:
            f.write("Valid3")
        subprocess.check_call(["git", "add", "valid3.txt"])
        subprocess.check_call(["git", "commit", "-m", "Valid 3"])

        self.assertTrue(self._get_trailer("Validated-At-Local"))
        self.assertEqual(self._get_trailer("PoW-Status"), "PASSED")

        # Now make the custom hook fail
        with open("custom_hook.sh", "w") as f:
            f.write("#!/bin/bash\nexit 1\n")

        with open("valid4.txt", "w") as f:
            f.write("Valid4")
        subprocess.check_call(["git", "add", "valid4.txt"])
        try:
            subprocess.check_call(["git", "commit", "-m", "Valid 4"])
            self.fail("Commit should have failed due to custom hook returning 1")
        except subprocess.CalledProcessError as e:
            self.assertNotEqual(e.returncode, 0)

    def test_session_ids_are_unique(self):
        """Each commit must get a different session UUID."""
        with open("file1.txt", "w") as f:
            f.write("A")
        subprocess.check_call(["git", "add", "file1.txt"])
        subprocess.check_call(["git", "commit", "-m", "Commit 1"])
        session_1 = self._get_trailer("PoW-Session")

        with open("file2.txt", "w") as f:
            f.write("B")
        subprocess.check_call(["git", "add", "file2.txt"])
        subprocess.check_call(["git", "commit", "-m", "Commit 2"])
        session_2 = self._get_trailer("PoW-Session")

        self.assertNotEqual(session_1, session_2)
        # They should look like UUIDs (36 chars, 4 dashes)
        self.assertEqual(len(session_1), 36)
        self.assertEqual(session_1.count("-"), 4)


if __name__ == "__main__":
    unittest.main()
