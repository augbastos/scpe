"""Pull the IBM Plex woff2 files this folder renders with into fonts/.

The materials used to @import the faces from Google Fonts at render time. That makes the
PNG export a race: if the stylesheet is slow the exporter screenshots the fallback face and
ships a card in a typeface the site does not use, silently and with no error anywhere. It is
exactly the kind of defect that only shows up when someone looks at the finished image.

Fonts live in the repo so a render is deterministic and offline. Re-run only to add a weight.

    python docs/brand/fetch-fonts.py
"""
import pathlib
import re
import urllib.request

UA = {"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")}
CSS = ("https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600"
       "&family=IBM+Plex+Mono:wght@400;500;600&display=block")

HERE = pathlib.Path(__file__).parent
OUT = HERE / "fonts"
OUT.mkdir(exist_ok=True)


def get(url: str) -> bytes:
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA)).read()


css = get(CSS).decode()

# Google emits one @font-face per subset, each preceded by a /* subset */ comment.
# Only latin is needed — the material is English — and taking every subset would multiply
# the download for glyphs no card contains.
blocks = re.split(r"/\*\s*([a-z-]+)\s*\*/", css)[1:]
faces = []
for subset, body in zip(blocks[0::2], blocks[1::2]):
    if subset != "latin":
        continue
    family = re.search(r"font-family:\s*'([^']+)'", body).group(1)
    weight = re.search(r"font-weight:\s*(\d+)", body).group(1)
    src = re.search(r"url\((https://[^)]+\.woff2)\)", body).group(1)
    name = f"{family.replace(' ', '')}-{weight}.woff2"
    (OUT / name).write_bytes(get(src))
    faces.append((family, weight, name, (OUT / name).stat().st_size))

for family, weight, name, size in sorted(faces):
    print(f"{family} {weight} -> fonts/{name}  ({size / 1024:.0f} KB)")
print(f"\n{len(faces)} faces")
