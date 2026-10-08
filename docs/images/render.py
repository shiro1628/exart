# 캡처한 터미널 출력(txt)을 터미널 모양 SVG로 그린다. 사용: python render.py <입력.txt> <출력.svg> <제목>  (pip install rich==13.9.4)
import re, sys
from rich.console import Console
from rich.text import Text
from rich.cells import cell_len

src, dst, title = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(src, encoding="utf-8").read().rstrip("\n").split("\n")
width = max(cell_len(l.expandtabs(8)) for l in lines) + 2
con = Console(record=True, width=width, force_terminal=True, color_system="truecolor", file=open("/dev/null", "w"))
for raw in lines:
    line = raw.expandtabs(8)
    t = Text(line)
    if re.match(r"^root@\S+#", line):
        p = line.index("#") + 1
        t.stylize("bold #7ee787", 0, p)
        t.stylize("bold", p)
    elif " W [" in line or line.lstrip().startswith(("[경고]", "[주의]")):
        t.stylize("#e3b341")
    elif " 수집 completed" in line or "불일치 0" in line:
        t.stylize("bold #7ee787")
    elif line.startswith(("====", " exart ")):
        t.stylize("bold #79c0ff")
    else:
        for m in re.finditer(r"\bok\b", line):
            t.stylize("#7ee787", m.start(), m.end())
        m = re.match(r"^(\S+ \S+ KST) (I) (\[\w+\])", line)
        if m:
            t.stylize("#8b949e", 0, m.end(1))
            t.stylize("#79c0ff", m.start(3), m.end(3))
        if ",True," in line:
            t.stylize("#ff7b72")
    con.print(t, soft_wrap=True)
svg = con.export_svg(title=title)
open(dst, "w", encoding="utf-8").write(svg)
print(dst, width)
