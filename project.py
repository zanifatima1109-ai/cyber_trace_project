"""
CyberTrace (Simple Version) - Digital Evidence Investigation Tool
-----------------------------------------------------------------
Uses only Python's built-in libraries (no installation needed).

What it does:
  1. Create / list investigation cases
  2. Scan a folder (read-only) and save SHA-256 hashes
  3. Verify files later and compare with the saved hash
  4. Show a timeline of file timestamps and events
  5. Flag files for further review (rule-based)
  6. Save a text report

IMPORTANT: This tool NEVER modifies or deletes the evidence files.
A matching hash supports content integrity only; it does not prove authenticity.
File timestamps are recorded metadata, not proof of who did what or when.
Flags are only reasons for human review, not proof of malware or guilt.
"""

import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent
DB_FILE = BASE_DIR / "cybertrace.db"
REPORT_DIR = BASE_DIR / "reports"
SAMPLE_DIR = BASE_DIR / "sample_evidence"

# Configurable rules for the suspicious file review
EXECUTABLE_EXT = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".dll", ".msi"}
UNUSUAL_EXT = {".locked", ".encrypted", ".tmp", ".xyz", ".crypt"}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ts(epoch):
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


# ----------------------------- DATABASE -----------------------------
def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS cases(
            case_id TEXT PRIMARY KEY, title TEXT, description TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, path TEXT, name TEXT,
            ext TEXT, size INTEGER, modified TEXT, changed TEXT,
            sha256 TEXT, hash_time TEXT);
        CREATE TABLE IF NOT EXISTS verifications(
            id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER, checked TEXT,
            new_hash TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, time TEXT,
            type TEXT, description TEXT);
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, action TEXT);
        """)


def log(action, case_id=None):
    """Audit log + (if a case is given) a timeline event."""
    with connect() as c:
        c.execute("INSERT INTO audit(time, action) VALUES (?, ?)", (now(), action))
        if case_id:
            c.execute("INSERT INTO events(case_id, time, type, description) VALUES (?,?,?,?)",
                      (case_id, now(), "Investigation event", action))


# ----------------------------- HASHING ------------------------------
def sha256_of(path):
    """Read the file in small chunks (read-only) and return its SHA-256."""
    h = hashlib.sha256()
    with open(path, "rb") as f:          # "rb" = read only, never writes
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------- FEATURES -----------------------------
def create_case():
    title = input("Case title: ").strip()
    if not title:
        print("  ! Title cannot be empty.")
        return
    desc = input("Description: ").strip()
    with connect() as c:
        count = c.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        case_id = f"CASE-{datetime.now().year}-{count + 1:03d}"
        c.execute("INSERT INTO cases VALUES (?,?,?,?)", (case_id, title, desc, now()))
    log(f"Case created: {case_id} - {title}", case_id)
    print(f"  ✓ Case created with ID: {case_id}")


def list_cases(search=""):
    with connect() as c:
        rows = c.execute(
            "SELECT * FROM cases WHERE case_id LIKE ? OR title LIKE ? ORDER BY created",
            (f"%{search}%", f"%{search}%")).fetchall()
    if not rows:
        print("  (no cases found)")
    for r in rows:
        print(f"  {r['case_id']} | {r['created']} | {r['title']}")
    return rows


def ask_case():
    list_cases()
    case_id = input("Enter Case ID: ").strip().upper()
    with connect() as c:
        if not c.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
            print("  ! Case not found. Create it first (menu option 1).")
            return None
    return case_id


def scan_folder():
    case_id = ask_case()
    if not case_id:
        return
    folder = Path(input("Folder to scan: ").strip().strip('"'))
    if not folder.is_dir():
        print("  ! That folder does not exist. Check the path and try again.")
        return
    count = errors = 0
    with connect() as c:
        for p in folder.rglob("*"):
            if not p.is_file():
                continue
            try:
                st = p.stat()
                digest = sha256_of(p)
                c.execute(
                    "INSERT INTO files(case_id,path,name,ext,size,modified,changed,sha256,hash_time)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (case_id, str(p), p.name, p.suffix.lower(), st.st_size,
                     ts(st.st_mtime), ts(st.st_ctime), digest, now()))
                count += 1
                print(f"  {p.name:<28}{st.st_size:>8} bytes  {digest[:16]}...")
            except (PermissionError, OSError) as e:
                errors += 1
                print(f"  ! Skipped {p.name}: {e}")
    log(f"Scanned folder {folder}: {count} files hashed, {errors} errors", case_id)
    print(f"  ✓ Done. {count} files saved, {errors} skipped.")


def verify_files():
    case_id = ask_case()
    if not case_id:
        return
    with connect() as c:
        files = c.execute("SELECT * FROM files WHERE case_id=?", (case_id,)).fetchall()
        if not files:
            print("  ! No scanned files for this case yet (use option 3).")
            return
        for f in files:
            try:
                new = sha256_of(f["path"])
                status = "MATCH" if new == f["sha256"] else "MISMATCH"
            except (FileNotFoundError, PermissionError, OSError):
                new, status = "", "UNREADABLE/MISSING"
            c.execute("INSERT INTO verifications(file_id,checked,new_hash,status) VALUES (?,?,?,?)",
                      (f["id"], now(), new, status))
            print(f"  [{status:<18}] {f['name']}")
    log(f"Integrity verification run for {len(files)} files", case_id)
    print("\n  NOTE: MATCH means the content is the same as the recorded baseline.")
    print("  It supports integrity but does NOT prove the evidence is authentic.")


def timeline():
    case_id = ask_case()
    if not case_id:
        return
    with connect() as c:
        items = [(r["modified"], "File modified (metadata)", r["name"], case_id)
                 for r in c.execute("SELECT * FROM files WHERE case_id=?", (case_id,))]
        items += [(r["changed"], "File created/changed (metadata)", r["name"], case_id)
                  for r in c.execute("SELECT * FROM files WHERE case_id=?", (case_id,))]
        items += [(r["time"], r["type"], r["description"], case_id)
                  for r in c.execute("SELECT * FROM events WHERE case_id=?", (case_id,))]
    keyword = input("Filter by keyword (Enter = show all): ").strip().lower()
    order = input("Sort: [a]scending or [d]escending? ").strip().lower()
    items = [i for i in items if keyword in (i[1] + i[2]).lower()]
    items.sort(key=lambda i: i[0], reverse=(order == "d"))
    print(f"\n  {'Date/Time':<20}{'Type':<34}{'Description'}")
    for t, typ, desc, cid in items:
        print(f"  {t:<20}{typ:<34}{desc}  [{cid}]")
    print("\n  NOTE: File timestamps are recorded metadata. They do not prove exactly")
    print("  when a person performed an action.")


def review_flags(case_id):
    """Return a list of (file name, reason). Flags need human interpretation."""
    flags = []
    with connect() as c:
        for f in c.execute("SELECT * FROM files WHERE case_id=?", (case_id,)):
            if f["ext"] in EXECUTABLE_EXT:
                flags.append((f["name"], f"Executable/script file type ({f['ext']})"))
            if f["ext"] in UNUSUAL_EXT:
                flags.append((f["name"], f"Unusual file extension ({f['ext']})"))
            if f["ext"] == "":
                flags.append((f["name"], "File has no extension"))
            if f["size"] == 0:
                flags.append((f["name"], "File is empty (0 bytes)"))
            if f["modified"] < f["changed"] and f["ext"]:
                pass  # modified-before-created can be normal after copying, so not flagged alone
            if f["name"].count(".") >= 2:
                flags.append((f["name"], "Double extension (possible disguised file type)"))
            bad = c.execute("SELECT 1 FROM verifications WHERE file_id=? AND status='MISMATCH'",
                            (f["id"],)).fetchone()
            if bad:
                flags.append((f["name"], "Hash changed since baseline"))
    return flags


def suspicious_review():
    case_id = ask_case()
    if not case_id:
        return
    flags = review_flags(case_id)
    if not flags:
        print("  No files met the review rules.")
    for name, reason in flags:
        print(f"  ⚑ {name}: {reason}")
    log(f"Suspicious file review run: {len(flags)} flags", case_id)
    print("\n  NOTE: A flag is only a reason for further examination. It does NOT")
    print("  mean a file is malware or that anyone is guilty.")


def make_report():
    case_id = ask_case()
    if not case_id:
        return
    REPORT_DIR.mkdir(exist_ok=True)
    out = REPORT_DIR / f"report_{case_id}.txt"
    with connect() as c:
        case = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        files = c.execute("SELECT * FROM files WHERE case_id=?", (case_id,)).fetchall()
        events = c.execute("SELECT * FROM events WHERE case_id=? ORDER BY time", (case_id,)).fetchall()
        vers = c.execute("""SELECT f.name, v.checked, v.status FROM verifications v
                            JOIN files f ON f.id=v.file_id WHERE f.case_id=? ORDER BY v.checked""",
                         (case_id,)).fetchall()
    lines = ["CYBERTRACE INVESTIGATION REPORT", "=" * 60,
             f"Case ID     : {case['case_id']}", f"Title       : {case['title']}",
             f"Description : {case['description']}", f"Opened      : {case['created']}",
             f"Report time : {now()}", "", "EVIDENCE FILE INVENTORY", "-" * 60]
    for f in files:
        lines += [f"{f['name']}  ({f['size']} bytes)",
                  f"   Modified (metadata): {f['modified']}",
                  f"   SHA-256: {f['sha256']}  (recorded {f['hash_time']})"]
    lines += ["", "INTEGRITY VERIFICATION RESULTS", "-" * 60]
    lines += [f"{v['checked']}  {v['name']}: {v['status']}" for v in vers] or ["(none run)"]
    lines += ["", "TIMELINE EVENTS", "-" * 60]
    lines += [f"{e['time']}  {e['description']}" for e in events]
    lines += ["", "SUSPICIOUS FILE REVIEW (for further examination only)", "-" * 60]
    lines += [f"{n}: {r}" for n, r in review_flags(case_id)] or ["(no flags)"]
    lines += ["", "DISCLAIMER", "-" * 60,
              "Automated findings require human interpretation. Matching hashes support",
              "integrity but do not prove authenticity. File timestamps are recorded",
              "metadata and may not reflect real user actions. Flags do not prove malware",
              "or criminal activity."]
    out.write_text("\n".join(lines), encoding="utf-8")
    log(f"Report generated: {out.name}", case_id)
    print(f"  ✓ Report saved to: {out}")


def make_samples():
    """Create harmless sample files for demonstration."""
    SAMPLE_DIR.mkdir(exist_ok=True)
    (SAMPLE_DIR / "notes.txt").write_text("Meeting notes - sample data\n")
    (SAMPLE_DIR / "photo_report.docx.exe").write_text("harmless fake file for demo\n")
    (SAMPLE_DIR / "data.csv").write_text("id,name\n1,Alice\n2,Bob\n")
    (SAMPLE_DIR / "empty.log").write_text("")
    (SAMPLE_DIR / "readme").write_text("no extension sample\n")
    log("Sample evidence files created")
    print(f"  ✓ Sample files created in: {SAMPLE_DIR}")
    print("    Use this folder path when scanning.")


def dashboard():
    with connect() as c:
        cases = c.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        files = c.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        checks = c.execute("SELECT COUNT(*) FROM verifications").fetchone()[0]
        recent = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 5").fetchall()
    print("\n" + "=" * 60)
    print("  CYBERTRACE - Digital Evidence Investigation System")
    print("=" * 60)
    print(f"  Cases: {cases}   Files scanned: {files}   Integrity checks: {checks}")
    print("  Recent activity:")
    for r in recent:
        print(f"    {r['time']}  {r['action']}")
    if not recent:
        print("    (none yet)")


def main():
    init_db()
    actions = {"1": create_case, "2": lambda: list_cases(input("Search (Enter = all): ")),
               "3": scan_folder, "4": verify_files, "5": timeline,
               "6": suspicious_review, "7": make_report, "8": make_samples}
    while True:
        dashboard()
        print("""
  1) Create case          5) Timeline
  2) List / search cases  6) Suspicious file review
  3) Scan folder          7) Generate report
  4) Verify hashes        8) Create sample evidence files
  0) Exit""")
        choice = input("\nChoose: ").strip()
        if choice == "0":
            print("Goodbye.")
            break
        if choice in actions:
            try:
                actions[choice]()
            except Exception as e:  # keep the app alive on unexpected errors
                print(f"  ! Unexpected error: {e}")
        else:
            print("  ! Invalid choice. Enter a number from the menu.")
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
