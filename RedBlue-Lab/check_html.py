import pathlib, re

VOID = {"br", "hr", "img", "meta", "link", "input", "col", "source"}
TAGRE = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:\"[^\"]*\"|[^>])*?)(/?)>")
ALLOWED = ["amp","lt","gt","quot","apos","nbsp","mdash","ndash","hellip",
           "middot","minus","rarr","larr","times","divide","#x27","#39"]

for p in sorted(pathlib.Path(__file__).parent.glob("*.html")):
    h = p.read_text(encoding="utf-8")
    stack, errs = [], []
    for m in TAGRE.finditer(h):
        closing, tag, sc = m.group(1) == "/", m.group(2).lower(), m.group(4) == "/"
        if tag in VOID or sc:
            continue
        ln = h[: m.start()].count("\n") + 1
        if not closing:
            stack.append((tag, ln))
        else:
            if not stack:
                errs.append(("extra-close", tag, ln)); continue
            if stack[-1][0] == tag:
                stack.pop()
            elif tag in [t for t, _ in stack]:
                while stack and stack[-1][0] != tag:
                    t, l = stack.pop()
                    errs.append(("unclosed", t, l, "closed by /" + tag))
                if stack: stack.pop()
            else:
                errs.append(("unmatched-close", tag, ln))

    print(f"=== {p.name} ({len(h)} bytes)")
    print("  mismatches :", len(errs))
    for e in errs[:20]: print("   ", e)
    if stack: print("  leftover   :", stack[:10])

    inner = "(?:" + "|".join(ALLOWED) + "|#\\d+)"
    bad = list(re.finditer(r"&(?!" + inner + r";)", h))
    print("  unescaped &:", len(bad))
    for b in bad[:10]:
        ln = h[: b.start()].count("\n") + 1
        print(f"     line {ln}: {h[max(0,b.start()-40):b.start()+25]!r}")

    # column width overflow
    over = 0
    for t in re.findall(r"<table[^>]*>(.*?)</table>", h, re.S):
        for r in re.findall(r"<tr>(.*?)</tr>", t, re.S):
            w = [float(x) for x in re.findall(r'<th[^>]*style="width:\s*([\d.]+)%', r)]
            if w and sum(w) > 100.5:
                over += 1
    print("  tables     :", len(re.findall(r"<table", h)), "| overflowing rows:", over)
    print()
