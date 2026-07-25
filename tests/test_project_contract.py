from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VALIDATE_PROJECT = REPOSITORY_ROOT / "scripts" / "validate_project.py"


class ProjectContractCommandTest(unittest.TestCase):
    def test_repository_configuration_matches_the_approved_security_contract(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(VALIDATE_PROJECT),
                "--root",
                str(REPOSITORY_ROOT),
            ],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("project contract is valid", result.stdout)


if __name__ == "__main__":
    unittest.main()
