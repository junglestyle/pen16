"""Render the dashboard's app icons from pen16-icon-dark.svg. `make icons` runs this; commit what it writes.

Phones don't use an SVG for a home screen icon, so these are PNGs: the light-on-dark mark on a solid square, with
room around it. iOS rounds the square's corners, and Android may crop a maskable icon to the circle inside its
middle 80%, so the maskable ones get more room.
"""

import math
import re
import sys
from pathlib import Path

import resvg_py

HERE = Path(__file__).parent
STATIC = HERE.parents[1] / "src" / "pen16" / "static"
BACKGROUND = "#1A1918"
# In the source's 120-unit viewBox, the plate (r 40 at 54,64) and the dot (r 6.6 at 101,17) fill a 93.6-unit
# square around this centre, and the dot's far edge is REACH from it.
CENTRE = (60.8, 57.2)
EXTENT = 93.6
REACH = math.dist(CENTRE, (101, 17)) + 6.6


def icon(side: float) -> str:
    """The mark centred on a square `side` units wide, with the background drawn in."""
    source = (HERE / "pen16-icon-dark.svg").read_text()
    inner = re.search(r"<svg[^>]*>(.*)</svg>", source, re.DOTALL)
    if inner is None:
        sys.exit("pen16-icon-dark.svg has no <svg> element")
    x, y = CENTRE[0] - side / 2, CENTRE[1] - side / 2
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x:.2f} {y:.2f} {side:.2f} {side:.2f}">'
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{side:.2f}" height="{side:.2f}" fill="{BACKGROUND}"/>'
        f"{inner.group(1)}</svg>"
    )


def main() -> None:
    STATIC.mkdir(exist_ok=True)
    # iOS: the mark fills 80% of the square; the dot stays inside the rounded corner.
    rounded = icon(EXTENT / 0.8)
    # Android maskable: everything inside the safe circle, radius 40% of the side.
    maskable = icon(REACH / 0.4)
    for name, svg, size in (
        ("apple-touch-icon.png", rounded, 180),
        ("icon-192.png", maskable, 192),
        ("icon-512.png", maskable, 512),
    ):
        (STATIC / name).write_bytes(bytes(resvg_py.svg_to_bytes(svg_string=svg, width=size, height=size)))
        print(f"wrote {name}")


if __name__ == "__main__":
    main()
