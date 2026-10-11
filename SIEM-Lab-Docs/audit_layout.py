import pathlib, re

d = pathlib.Path(r"C:\Users\pc\Desktop\SIEM-Lab-Docs")

for f in sorted(d.glob("pdf*.html")):
    html = f.read_text(encoding="utf-8")
    print(f"=== {f.name} ===")

    # 1) column width audit: any row whose fixed widths exceed 100%
    bad = 0
    tables = re.findall(r"<table[^>]*>(.*?)</table>", html, re.S)
    for t in tables:
        rows = re.findall(r"<tr>(.*?)</tr>", t, re.S)
        for r in rows:
            widths = [float(x) for x in re.findall(r'<th[^>]*style="width:\s*([\d.]+)%', r)]
            if widths and sum(widths) > 100.5:
                bad += 1
                print(f"  OVERFLOW: {sum(widths):.1f}%  {widths}")
    print(f"  tables: {len(tables)}, rows overflowing 100%: {bad}")

    # 2) unbalanced tag check for the main containers
    for tag in ("table", "tr", "td", "th", "pre", "div", "ul", "ol", "li"):
        o = len(re.findall(rf"<{tag}[\s>]", html))
        c = len(re.findall(rf"</{tag}>", html))
        flag = "" if o == c else "   <-- MISMATCH"
        print(f"  <{tag}>: {o} open / {c} close{flag}")

    # 3) raw ampersands or stray unescaped chars in text (render as artefacts)
    stray = len(re.findall(r"&(?!(amp|lt|gt|quot|apos|nbsp|mdash|ndash|hellip|middot|rarr|#\d+);)\w", html))
    print(f"  unescaped & : {stray}")

    # 4) entities used
    ents = sorted(set(re.findall(r"&([a-zA-Z]+);", html)))
    print(f"  entities    : {', '.join(ents)}")
    print()
