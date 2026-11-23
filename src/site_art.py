"""Local deterministic SVG artwork for the version-one site generator.

These are decorative studies, not photographs, astronomical charts or maps.
No user text, external image/font references, scripts or installation secrets
are interpolated into the SVG. Geometry and colours are bounded and validated.
"""
from __future__ import annotations

import hashlib as _art_hashlib
import re as _art_re


_ART_THEMES = (
    "journal", "botanical", "photography", "architecture", "astronomy",
    "typography", "cartography", "ceramics", "coffee", "acoustics", "printmaking", "coastal",
)


def _art_inputs(seed, theme, colors):
    if not isinstance(seed, str) or not _art_re.fullmatch(r"[0-9a-f]{64}", seed):
        raise ValueError("Artwork seed must be 64 lowercase hexadecimal characters")
    if not isinstance(theme, str) or theme not in _ART_THEMES:
        raise ValueError("Unsupported artwork theme")
    if not isinstance(colors, (tuple, list)) or len(colors) != 6:
        raise ValueError("Artwork palette must have six colours")
    if any(not isinstance(c, str) or not _art_re.fullmatch(r"#[0-9A-Fa-f]{6}", c) for c in colors):
        raise ValueError("Artwork colours must be six-digit hexadecimal values")


def _art_n(seed, key, low, high):
    digest = _art_hashlib.sha256(("art-v1\0" + seed + "\0" + key).encode()).hexdigest()
    return low + int(digest[:16], 16) % (high - low + 1)


def render_site_illustration(seed: str, theme: str, colors) -> str:
    """Return a decorative 960x600 study, varied by the installation seed."""
    _art_inputs(seed, theme, colors)
    bg, ink, muted, accent, panel, border = colors
    n = lambda key, low, high: _art_n(seed, key, low, high)
    elements = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 600" role="img" aria-labelledby="art-title">',
        '<title id="art-title">An abstract ' + theme + ' study</title>',
        f'<rect width="960" height="600" fill="{panel}"/>',
    ]
    add = elements.append
    if theme == "journal":
        for i in range(3):
            x, y = 145 + i * 194 + n(f"x{i}", -22, 22), 80 + n(f"y{i}", 0, 55)
            w, h = n(f"w{i}", 220, 260), n(f"h{i}", 320, 390)
            angle = n(f"angle{i}", -8, 8)
            add(f'<g transform="rotate({angle} {x+w//2} {y+h//2})">')
            add(f'<rect x="{x+8}" y="{y+12}" width="{w}" height="{h}" fill="{border}"/>')
            add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{bg}"/>')
            add(f'<rect x="{x+27}" y="{y+35}" width="{n(f"head{i}",65,115)}" height="8" fill="{accent}"/>')
            for j in range(7):
                width = n(f"line{i}:{j}", 75, w - 55)
                add(f'<path d="M{x+27} {y+82+j*30}h{width}" stroke="{muted}" stroke-width="2" opacity=".5"/>')
            add('</g>')
    elif theme == "botanical":
        for i in range(5):
            x, top = 185 + i * 148 + n(f"stem{i}", -20, 20), n(f"top{i}", 90, 210)
            bend = n(f"bend{i}", -65, 65)
            add(f'<path d="M{x} 535 Q{x+bend} 320 {x+bend//2} {top}" fill="none" stroke="{accent}" stroke-width="5"/>')
            for j in range(5):
                y, side = 460 - j * 62, 1 if j % 2 else -1
                dx, dy = n(f"leafx{i}:{j}", 45, 85) * side, n(f"leafy{i}:{j}", 22, 48)
                add(f'<path d="M{x} {y} Q{x+dx} {y-dy-45} {x+dx} {y-dy} Q{x+dx//2} {y+12} {x} {y}Z" fill="{accent if j%2 else muted}" opacity=".75"/>')
        add(f'<path d="M100 537h760" stroke="{border}" stroke-width="2"/>')
    elif theme == "photography":
        x, y = n("lightx", 220, 720), n("lighty", 130, 270)
        add(f'<rect x="110" y="60" width="740" height="480" rx="2" fill="{bg}"/>')
        add(f'<circle cx="{x}" cy="{y}" r="{n("radius",55,105)}" fill="{accent}" opacity=".65"/>')
        add(f'<path d="M110 420 Q310 {n("hill1",170,310)} 520 400 T850 390V540H110Z" fill="{border}"/>')
        add(f'<path d="M110 480 Q400 {n("hill2",320,420)} 850 450V540H110Z" fill="{muted}" opacity=".7"/>')
        add(f'<rect x="145" y="95" width="670" height="410" fill="none" stroke="{bg}" stroke-width="2" opacity=".8"/>')
        add(f'<path d="M480 120v360M170 300h620" stroke="{bg}" stroke-width="1" opacity=".45"/>')
    elif theme == "architecture":
        ground = 515
        for i in range(5):
            x, width, height = 110 + i * 151, n(f"width{i}", 100, 137), n(f"height{i}", 175, 385)
            y = ground - height
            add(f'<rect x="{x+13}" y="{y+16}" width="{width}" height="{height-16}" fill="{border}"/>')
            add(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" fill="{bg if i%2 else accent}"/>')
            for row in range((height - 30) // 47):
                for col in range(2):
                    add(f'<rect x="{x+22+col*49}" y="{y+25+row*47}" width="21" height="25" fill="{ink}" opacity=".18"/>')
        add(f'<path d="M70 {ground}h820" stroke="{muted}" stroke-width="3"/>')
    elif theme == "astronomy":
        add(f'<rect width="960" height="600" fill="{ink}"/>')
        points = []
        for i in range(46):
            x, y = n(f"sx{i}", 65, 895), n(f"sy{i}", 55, 545)
            radius = n(f"sr{i}", 12, 34) / 10
            add(f'<circle cx="{x}" cy="{y}" r="{radius:.1f}" fill="{bg}" opacity=".{n(f"so{i}",40,95)}"/>')
            if i < 6:
                points.append(f"{x},{y}")
        add(f'<polyline points="{" ".join(points)}" fill="none" stroke="{border}" stroke-width="1" opacity=".3"/>')
        x, y, r = n("moonx", 230, 740), n("moony", 160, 380), n("moonr", 55, 85)
        add(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{panel}"/>')
        add(f'<circle cx="{x+r//2}" cy="{y-r//5}" r="{r-4}" fill="{ink}"/>')
    elif theme == "typography":
        add(f'<rect x="100" y="65" width="760" height="470" fill="{bg}"/>')
        for y in (165, 300, 450):
            add(f'<path d="M145 {y}h670" stroke="{border}" stroke-width="2"/>')
        pairs = ("Aa", "Gg", "Rr", "Mm", "Ee", "Bb")
        pair = pairs[n("glyphs", 0, len(pairs)-1)]
        add(f'<text x="{n("textx",160,220)}" y="445" font-family="Georgia,serif" font-size="{n("size",300,350)}" fill="{ink}">{pair}</text>')
        add(f'<circle cx="{n("dotx",700,790)}" cy="{n("doty",135,220)}" r="{n("dotr",22,38)}" fill="{accent}"/>')
    elif theme == "cartography":
        for i in range(10):
            y = 50 + i * 55
            offset = n(f"contour{i}", -45, 45)
            add(f'<path d="M-20 {y} C220 {y-150+offset} 275 {y+130} 510 {y+offset} S780 {y-115} 980 {y+55}" fill="none" stroke="{accent if i%3==0 else muted}" stroke-width="{2 if i%3==0 else 1}" opacity=".7"/>')
        x = n("route", 370, 580)
        add(f'<path d="M120 590 Q{x-140} 380 {x} 290 T820 10" fill="none" stroke="{bg}" stroke-width="13"/>')
        add(f'<path d="M120 590 Q{x-140} 380 {x} 290 T820 10" fill="none" stroke="{border}" stroke-width="3"/>')
        for i in range(4):
            add(f'<circle cx="{n(f"px{i}",160,800)}" cy="{n(f"py{i}",90,510)}" r="5" fill="{ink}"/>')
    elif theme == "ceramics":
        for i in range(3):
            x, top, half = 235 + i * 245, n(f"top{i}", 125, 250), n(f"half{i}", 48, 72)
            belly = n(f"belly{i}", 88, 112)
            fill = (accent, muted, bg)[i]
            add(f'<ellipse cx="{x+7}" cy="500" rx="{belly}" ry="17" fill="{border}"/>')
            add(f'<path d="M{x-half} {top} Q{x-half+13} {top+70} {x-belly} 350 Q{x-belly-12} 470 {x-55} 489 H{x+55} Q{x+belly+12} 470 {x+belly} 350 Q{x+half-13} {top+70} {x+half} {top}Z" fill="{fill}"/>')
            add(f'<ellipse cx="{x}" cy="{top}" rx="{half}" ry="14" fill="{ink}" opacity=".3"/>')
            add(f'<path d="M{x-belly+15} 380h{2*belly-30}M{x-belly+18} 400h{2*belly-36}" stroke="{panel}" stroke-width="2" opacity=".5"/>')
    elif theme == "coffee":
        for i in range(3):
            x, y, r = 230 + i * 250, n(f"cy{i}", 235, 365), n(f"cr{i}", 58, 76)
            add(f'<ellipse cx="{x+5}" cy="{y+16}" rx="{r+35}" ry="{r+24}" fill="{border}"/>')
            add(f'<circle cx="{x}" cy="{y}" r="{r+25}" fill="{bg}"/>')
            add(f'<ellipse cx="{x+r}" cy="{y}" rx="25" ry="21" fill="none" stroke="{muted}" stroke-width="10"/>')
            add(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{muted}"/>')
            add(f'<circle cx="{x}" cy="{y}" r="{r-12}" fill="{ink}"/>')
            add(f'<path d="M{x-r//3} {y} Q{x} {y-r//2} {x+r//3} {y} T{x-r//3} {y+r//3}" fill="none" stroke="{panel}" stroke-width="5" opacity=".7"/>')
        for i in range(8):
            x, y = n(f"beanx{i}", 110, 850), n(f"beany{i}", 440, 520)
            add(f'<ellipse cx="{x}" cy="{y}" rx="11" ry="7" fill="{accent}" transform="rotate({n(f"beana{i}",0,160)} {x} {y})"/>')
    elif theme == "acoustics":
        add(f'<path d="M75 300h810" stroke="{border}" stroke-width="2"/>')
        for i in range(47):
            x = 85 + i * 17
            height = n(f"amplitude{i}", 15, 205)
            add(f'<path d="M{x} {300-height}v{height*2}" stroke="{accent if i%3 else muted}" stroke-width="{n(f"stroke{i}",4,9)}" stroke-linecap="round" opacity=".8"/>')
        add(f'<path d="M80 530h800" stroke="{muted}" stroke-width="2"/>')
        for i in range(9):
            add(f'<path d="M{80+i*100} 522v16" stroke="{muted}" stroke-width="2"/>')
    elif theme == "printmaking":
        for i in range(8):
            x, y = 100 + (i % 4) * 195, 100 + (i // 4) * 225
            width, height = n(f"pw{i}", 120, 165), n(f"ph{i}", 140, 185)
            fill = (accent, muted, ink)[i % 3]
            add(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" fill="{fill}" opacity=".8" transform="rotate({n(f"pa{i}",-4,4)} {x+width//2} {y+height//2})"/>')
            for j in range(4):
                add(f'<path d="M{x+15} {y+30+j*32}q{width//3} {n(f"curve{i}:{j}",-20,20)} {width-30} 0" fill="none" stroke="{panel}" stroke-width="3" opacity=".75"/>')
    elif theme == "coastal":
        add(f'<rect width="960" height="600" fill="{bg}"/>')
        for i in range(7):
            y, drift = 110 + i * 70, n(f"wave{i}", -40, 40)
            add(f'<path d="M-20 {y} Q220 {y-65+drift} 470 {y+10} T980 {y-5} V620H-20Z" fill="{accent if i%2 else muted}" opacity=".23"/>')
            add(f'<path d="M-20 {y} Q220 {y-65+drift} 470 {y+10} T980 {y-5}" fill="none" stroke="{bg}" stroke-width="{n(f"foam{i}",2,5)}" opacity=".7"/>')
        for i in range(8):
            add(f'<ellipse cx="{n(f"pebblex{i}",70,890)}" cy="{n(f"pebbley{i}",490,555)}" rx="{n(f"pr{i}",8,21)}" ry="{n(f"ph{i}",4,11)}" fill="{ink}" opacity=".25"/>')
    add('</svg>\n')
    return '\n'.join(elements)


def render_site_icon(seed: str, theme: str, colors) -> str:
    """A compact thematic favicon drawn entirely from validated primitives."""
    _art_inputs(seed, theme, colors)
    bg, ink, muted, accent, panel, border = colors
    radius = _art_n(seed, "icon-corner", 10, 23)
    motifs = {
        "journal": '<path d="M20 18h24v30H20zM25 26h14M25 32h11M25 38h14"/>',
        "botanical": '<path d="M31 48V20M31 35Q12 32 18 20Q32 20 31 35M31 42Q49 39 47 27Q32 27 31 42"/>',
        "photography": '<rect x="16" y="19" width="32" height="27" rx="3"/><circle cx="32" cy="33" r="8"/>',
        "architecture": '<path d="M17 47V28h10v19M28 47V16h10v31M39 47V24h9v23"/>',
        "astronomy": '<path d="M38 15A18 18 0 1 0 48 42A20 20 0 0 1 38 15Z"/>',
        "typography": '<path d="M17 47L30 16h4l13 31M23 34h18"/>',
        "cartography": '<path d="M12 22q15-18 28 0t16 4M10 34q15-18 28 0t18 4M10 46q15-18 28 0t16 4"/>',
        "ceramics": '<path d="M24 17h16q-2 11 4 20q4 12-12 12T20 37q6-9 4-20Z"/>',
        "coffee": '<path d="M18 25h25v14q0 10-12 10T18 39ZM43 27q15-2 10 10q-3 5-10 2M25 12v6M34 12v6"/>',
        "acoustics": '<path d="M16 25v14M24 16v32M32 22v20M40 12v40M48 25v14"/>',
        "printmaking": '<path d="M16 17h14v14H16ZM35 17h13v14H35ZM16 36h14v13H16ZM35 36h13v13H35Z"/>',
        "coastal": '<path d="M10 22q11-10 22 0t22 0M10 33q11-10 22 0t22 0M10 44q11-10 22 0t22 0"/>',
    }
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            f'<rect width="64" height="64" rx="{radius}" fill="{accent}"/>'
            f'<g fill="none" stroke="{bg}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">'
            + motifs[theme] + '</g></svg>\n')
