import pathlib, re, sys, zlib

d = pathlib.Path(r"C:\Users\pc\Desktop\SIEM-Lab-Docs")

for p in sorted(d.glob("*.pdf")):
    b = p.read_bytes()
    pages = len(re.findall(rb"/Type\s*/Page[^sC]", b))
    counts = [int(x) for x in re.findall(rb"/Count\s+(\d+)", b)]
    ver = b[8:12].decode("latin1")
    print(f"{p.name}")
    print(f"   pdf version : {ver}")
    print(f"   page objects: {pages}")
    print(f"   /Count vals : {sorted(set(counts), reverse=True)[:3]}")
    print(f"   size        : {len(b)/1024:.0f} KB")
    print(f"   EOF marker  : {b.rstrip()[-6:] == b'%%EOF'}")
    # sanity: decompress first content stream to prove it renders text
    streams = re.findall(rb"stream\r?\n(.*?)endstream", b, re.S)
    text_found = False
    for s in streams[:60]:
        try:
            d2 = zlib.decompress(s)
            if b"Tj" in d2 or b"TJ" in d2:
                text_found = True
                break
        except Exception:
            pass
    print(f"   text in PDF : {text_found}")
    print()
