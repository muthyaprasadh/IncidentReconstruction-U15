"""
Launch Script for U-15 Incident Reconstruction Platform.
Usage:
    python run.py
"""
import sys
import os
import subprocess
from pathlib import Path

def main():
    root_dir = Path(__file__).resolve().parent
    os.chdir(root_dir)
    sys.path.insert(0, str(root_dir))

    # Pre-initialize database
    import database.db as db
    db.init_db()

    app_path = root_dir / "app" / "main.py"
    
    cmd = [
        sys.executable,
        "-m", "streamlit", "run",
        str(app_path),
        "--server.headless=false",
        "--theme.base=dark"
    ]

    print(f"[*] Starting U-15 Incident Reconstruction Platform on http://localhost:8501 ...")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[*] Application shutdown safely.")

if __name__ == "__main__":
    main()
