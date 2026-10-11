import pathlib, subprocess, sys, re, shutil, time

BASE = pathlib.Path(r"C:\Users\pc\Desktop\SIEM-Lab-Docs")
CSS = (BASE / "style.css").read_text(encoding="utf-8")

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PROFILE = pathlib.Path(r"C:\Users\pc\AppData\Local\Temp\opencode\edge-pdf-profile")

DOCS = [
    ("pdf1-wazuh-guide.html", "Wazuh-4.14.8-Lab-Guide.pdf"),
    ("pdf2-winserver-hardening.html",
     "Windows-Server-2022-Hardening-and-Detection-Lab.pdf"),
    ("pdf3-redteam-attack.html",
     "Attacking-Windows-Server-2022-RedTeam-Companion.pdf"),
    ("pdf4-live-exploitation-runbook.html",
     "Attack-and-Watch-Live-Exploitation-Runbook.pdf"),
    ("pdf5-wazuh-detection-companion.html",
     "Wazuh-Detection-Companion-for-Windows-Attacks.pdf"),
]


def build_html(src: pathlib.Path) -> pathlib.Path:
    html = src.read_text(encoding="utf-8")
    # inline the stylesheet so headless rendering does not depend on file access
    html = re.sub(
        r'<link rel="stylesheet" href="style\.css">',
        "<style>\n" + CSS + "\n</style>",
        html,
    )
    out = BASE / ("_render_" + src.name)
    out.write_text(html, encoding="utf-8")
    return out


def wait_for_pdf(pdf: pathlib.Path, timeout: float = 60.0) -> int:
    """Edge/Chrome return from --print-to-pdf before the file is flushed,
    so poll until the size stops growing and the file is a plausible PDF."""
    deadline = time.time() + timeout
    last = -1
    stable = 0
    while time.time() < deadline:
        if pdf.exists():
            size = pdf.stat().st_size
            if size > 20_000 and size == last:
                stable += 1
                if stable >= 3:
                    return size
            else:
                stable = 0
            last = size
        time.sleep(0.5)
    return pdf.stat().st_size if pdf.exists() else 0


def main() -> int:
    if not pathlib.Path(EDGE).exists():
        print("Edge not found:", EDGE)
        return 1

    if PROFILE.exists():
        shutil.rmtree(PROFILE, ignore_errors=True)

    ok = True
    for src_name, pdf_name in DOCS:
        src = BASE / src_name
        if not src.exists():
            print("MISSING", src)
            ok = False
            continue

        rendered = build_html(src)
        pdf = BASE / pdf_name
        if pdf.exists():
            pdf.unlink()

        cmd = [
            EDGE,
            "--headless=new",
            f"--user-data-dir={PROFILE}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=15000",
            "--no-pdf-header-footer",
            f"--print-to-pdf={pdf}",
            rendered.as_uri(),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        size = wait_for_pdf(pdf)

        if size > 20_000:
            with pdf.open("rb") as fh:
                magic = fh.read(5)
            if magic == b"%PDF-":
                print(f"OK   {pdf_name}  ({size // 1024} KB)")
            else:
                ok = False
                print(f"FAIL {pdf_name}: not a PDF (magic={magic!r})")
        else:
            ok = False
            print(f"FAIL {pdf_name}: size={size}")
            print("stdout:", (proc.stdout or "")[:1500])
            print("stderr:", (proc.stderr or "")[:1500])
        time.sleep(1)

    shutil.rmtree(PROFILE, ignore_errors=True)
    for src_name, _ in DOCS:
        tmp = BASE / ("_render_" + src_name)
        if tmp.exists():
            tmp.unlink()

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
