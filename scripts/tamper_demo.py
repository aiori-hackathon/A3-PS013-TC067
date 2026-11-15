import argparse
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from forensic.ingest import verify_items


def _remove_readonly(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Demonstrate forensic evidence tamper detection.")
    parser.add_argument("--case", default="cases/s3_clock_skew", help="Path to case directory")
    args = parser.parse_args()

    case_path = Path(args.case)
    if not case_path.exists() or not case_path.is_dir():
        print(f"Error: Case directory not found: {case_path}", file=sys.stderr)
        sys.exit(1)

    tmp_dir = tempfile.mkdtemp(prefix="forensic_tamper_")
    try:
        copy_dir = Path(tmp_dir) / case_path.name
        shutil.copytree(case_path, copy_dir)

        print("Step 1: verify original evidence")
        res1 = verify_items(copy_dir)
        for item in res1:
            print(f"  {item.get('file')}: {item.get('status')}")

        evidence_dir = copy_dir / "evidence"
        stored_files = [p for p in evidence_dir.iterdir() if p.is_file()]
        if not stored_files:
            print("Error: No evidence files found in copy.", file=sys.stderr)
            sys.exit(1)

        target_file = stored_files[0]
        os.chmod(target_file, 0o644)
        with open(target_file, "ab") as f:
            f.write(b"X")
        print(f"Step 2: appended 1 byte to {target_file.name}")

        print("Step 3: verify again")
        res2 = verify_items(copy_dir)
        for item in res2:
            print(f"  {item.get('file')}: {item.get('status')}")

        has_tamper = any(item.get("status") != "OK" for item in res2)
        if has_tamper:
            print("Tamper detected: YES")
            sys.exit(0)
        else:
            print("Tamper detected: NO")
            sys.exit(1)
    finally:
        try:
            shutil.rmtree(tmp_dir, onexc=_remove_readonly)
        except TypeError:
            shutil.rmtree(tmp_dir, onerror=_remove_readonly)
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()

