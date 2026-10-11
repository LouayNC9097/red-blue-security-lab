"""Inject the real Install-WazuhAgent.ps1 source into the HTML, replacing the
hand-typed copy in section 7.4. Keeps the PDF and the script from drifting."""
import pathlib, re, html

BASE = pathlib.Path(__file__).resolve().parent
html_path = BASE / "red-blue-agent-install.html"
ps_path = BASE / "Install-WazuhAgent.ps1"

doc = html_path.read_text(encoding="utf-8")
src = ps_path.read_text(encoding="utf-8").rstrip("\n")

# syntax-highlight lightly for the dark <pre> block
def hi(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"(&lt;#[\s\S]*?#&gt;)", r'<span class="cmt">\1</span>', s)
    s = re.sub(r"^(\s*)(#[^\n]*)", r'\1<span class="cmt">\2</span>', s, flags=re.M)
    s = re.sub(r"(\`(n|[^\`]*\`n)?)", lambda m: '<span class="prm">' + m.group(1) + "</span>" if m.group(1) else m.group(1), s)
    s = s.replace("Write-Ok", '<span class="out">Write-Ok</span>')
    s = s.replace("Write-Bad", '<span class="erro">Write-Bad</span>')
    s = s.replace("exit 1", '<span class="erro">exit 1</span>')
    return s

body = "\n".join(hi(line) for line in src.split("\n"))

pat = re.compile(
    r'(<h2>7\.4 The complete script, for reference</h2>.*?<pre>)[\s\S]*?(</pre>)',
    re.S,
)
if not pat.search(doc):
    raise SystemExit("section 7.4 <pre> block not found")

new = pat.sub(lambda m: m.group(1) + body + m.group(2), doc, count=1)
html_path.write_text(new, encoding="utf-8")

print(f"injected {len(src.splitlines())} script lines into section 7.4")
