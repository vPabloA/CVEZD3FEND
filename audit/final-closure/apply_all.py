from pathlib import Path
import runpy

root = Path(__file__).resolve().parent
scripts = (
    "source_01.py",
    "source_02.py",
    "source_03a.py",
    "source_03b.py",
    "source_03c.py",
    "tests_01a.py",
    "tests_01b.py",
    "tests_02a.py",
    "tests_02b.py",
    "tests_02c_review.py",
    "tests_02c_ai.py",
)
for script in scripts:
    runpy.run_path(str(root / script), run_name="__main__")
