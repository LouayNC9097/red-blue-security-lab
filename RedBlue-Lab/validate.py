import pathlib, re, sys
from pypdf import PdfReader

sys.stdout.reconfigure(encoding="utf-8")

p = pathlib.Path(r"C:\Users\pc\Desktop\RedBlue-Lab\RedBlue-Lab-Vol3-Wazuh-Agent-Windows-Install.pdf")
r = PdfReader(str(p))
pages = [pg.extract_text() or "" for pg in r.pages]
t = "\n".join(pages)

print("pages:", len(r.pages))
print("encrypted:", r.is_encrypted)
print("chars:", len(t))
print("near-empty pages:", sum(1 for x in pages if len(x.strip()) < 200))
print("has WazuhSvc:", "WazuhSvc" in t)
print("has ossec.log:", "ossec.log" in t)
print("has WinServer:", "WinServer" in t)
print("has winsrv-01:", "winsrv-01" in t)
print("has wincli-01:", "wincli-01" in t)
print("has 1514:", "1514" in t)
print("has 55000:", "55000" in t)
print("first 240:", repr(t[:240]))
print("last 160:", repr(t[-160:]))
