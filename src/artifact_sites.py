"""Version-two static collections whose content is an actual generated artifact.

Everything is local and deterministic: SVG, usable CSS, parameter JSON and
descriptions are derived from the same bounded data.  No network, model API,
invented people, clients, publication dates or commercial claims are used.
Version-one content lives in rendering.py and is deliberately unchanged.
"""
from __future__ import annotations

import colorsys as _as_colorsys
import hashlib as _as_hashlib
import html as _as_html
import json as _as_json
import re as _as_re
from pathlib import PurePosixPath as _ASPath


ARTIFACT_THEMES = ("generative", "patterns", "palettes", "curves")
_AS_LAYOUTS = ("editorial", "gallery", "index", "notebook", "bulletin", "folio")
_AS_KEYS = {"version", "seed", "theme", "title", "description", "layout", "palette"}
_AS_PALETTES = {
    "chalk-blue": ("#F3F1EA", "#26333C", "#63747E", "#3E6C83", "#E0E7E8", "#CAD3D4"),
    "warm-clay": ("#F5EEE5", "#3A302C", "#7B685E", "#9F5D41", "#EBDBCF", "#D7C3B4"),
    "sage-paper": ("#EFF1E6", "#2B382E", "#65735D", "#54734F", "#DFE5D3", "#C8D2BC"),
    "rose-ink": ("#F4EDF0", "#3E303B", "#7F6878", "#86536E", "#E8DCE3", "#D7C5D0"),
    "night-blue": ("#142332", "#EEEAE0", "#AEC0CE", "#CDAE73", "#243C50", "#3A5266"),
}
_AS_CONTENT = {
    "generative": {
        "names": ("Form Sequences", "Geometric Studies", "A Small Shape Archive", "Ordered Variations", "Fields of Form"),
        "descriptions": ("Original geometric compositions with their coordinates, colours, and downloadable SVG files.",
                         "A collection of circle fields, bar rhythms, and nested frames built from explicit parameters.",
                         "Small studies in repetition and proportion, with the source data beside each image."),
        "eyebrow": "Geometry / repetition / proportion",
        "methods": ("circle-grid", "bar-field", "nested-frames"),
        "about": "This collection treats a geometric composition as both an image and a set of decisions. Every study includes the actual coordinates, dimensions and colours used to draw it.",
        "method_text": "Circles are placed on a regular grid, bars share a baseline, and nested frames use progressively inset rectangles. The parameter JSON records every primitive so changes can be compared coordinate by coordinate.",
        "editing": "Open the SVG in a vector editor to move, resize, or recolour its circles, bars, or frames. The JSON lists each primitive's coordinates and colours, providing a reference when making a related variation.",
    },
    "patterns": {
        "names": ("Repeat Studies", "The Pattern Shelf", "Tiles in Sequence", "Small Repeats", "A Repeating Field"),
        "descriptions": ("Original repeating SVG tiles, full-field previews, and CSS ready for a local project.",
                         "Dot grids, diagonal stripes, and Truchet tiles with their dimensions and repeat rules.",
                         "A small library of geometric surface patterns with real downloadable source files."),
        "eyebrow": "Tile / repeat / surface",
        "methods": ("dot-grid", "diagonal-stripes", "truchet"),
        "about": "Each item is a real repeating tile. Its large preview is drawn by repeating the same SVG geometry that is available for download, so the preview and the usable material stay connected.",
        "method_text": "Dot tiles repeat a centred circle. The vertical offset between consecutive stripes divides the tile size exactly. Truchet arcs meet the midpoint of each cell edge, including the outer boundary. The SVG viewport clips each tile; the supplied CSS repeats it at its recorded dimensions.",
        "editing": "Keep the SVG and CSS in the same directory and apply the study-pattern class to an element with a defined size. Edit fill and stroke values in the SVG to change its colours. When changing tile geometry, preserve the connections at opposite edges to keep the repeat continuous.",
    },
    "palettes": {
        "names": ("Colour Sets", "The Palette Notebook", "Measured Colours", "Small Colour Collections", "Colour Relationships"),
        "descriptions": ("Generated colour sets with exact hex values, CSS variables, and measured contrast pairs.",
                         "Analogous, split-complementary, and monochrome colour studies with reusable downloads.",
                         "A collection of colour relationships whose numbers match the swatches on the page."),
        "eyebrow": "Hue / lightness / contrast",
        "methods": ("analogous", "split-complementary", "monochrome"),
        "about": "These studies begin with explicit hue, saturation and lightness steps. The displayed sRGB hex colours, exported CSS variables and measured contrast matrix all come from the same final values.",
        "method_text": "HSL values are converted to eight-bit sRGB colours. Relative luminance and contrast are calculated from those final hex values using the WCAG sRGB formula. A ratio describes a colour pair; it does not certify the accessibility of a whole design.",
        "editing": "Copy the supplied --study-color-1 through --study-color-5 CSS variables into a stylesheet and assign them to text, backgrounds, or borders. If you change a hex value, calculate its contrast again before choosing a text and background pair.",
    },
    "curves": {
        "names": ("Curve Studies", "The Control Point Archive", "Lines in Motion", "A Bezier Collection", "Paths and Handles"),
        "descriptions": ("Original cubic Bezier studies with explicit control points and editable SVG paths.",
                         "Single curves, mirrored pairs, and curve bundles with the data needed to inspect their construction.",
                         "A small collection of parameter-based line studies, from control polygons to finished curves."),
        "eyebrow": "Endpoint / handle / curve",
        "methods": ("single-cubic", "mirrored-pair", "curve-bundle"),
        "about": "A curve is presented together with the four points that define it. The collection uses cubic Bezier paths so that each drawing can be inspected, edited, and reproduced from its parameter file.",
        "method_text": "Each path begins at P0 and ends at P3; P1 and P2 are its control points. Mirrored pairs reflect those points across the vertical centreline. Bundles vary the control points while retaining a shared start and end. Moving an inner control point reshapes the curve while its endpoints keep their positions.",
        "editing": "Edit the two inner coordinate pairs after the SVG path's C command to move its control points. The JSON records all four points in order, so you can compare the curve before and after an edit. Use the matching CSS to place the resulting SVG as a background.",
    },
}


def _as_digest(seed, label):
    return _as_hashlib.sha256(("artifact-site-v2\0" + seed + "\0" + label).encode()).hexdigest()


def _as_n(seed, label, low, high):
    return low + int(_as_digest(seed, label)[:16], 16) % (high - low + 1)


def _as_pick(seed, label, values):
    return values[_as_n(seed, label, 0, len(values) - 1)]


def _as_seed(seed):
    if not isinstance(seed, str) or not _as_re.fullmatch(r"[0-9a-f]{64}", seed):
        raise ValueError("Artifact-site seed must contain exactly 64 lowercase hexadecimal characters")
    return seed


def _as_text(value, name, limit, normalize=False):
    if not isinstance(value, str) or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in value):
        raise ValueError("Invalid artifact-site " + name)
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Artifact-site text must be valid UTF-8") from exc
    if normalize:
        value = " ".join(value.split())
    if not value or len(value) > limit or value != " ".join(value.split()):
        raise ValueError(f"Artifact-site {name} must contain 1–{limit} normalized characters")
    return value


def _as_domain(value):
    if not isinstance(value, str) or not value.isascii() or value != value.strip() or len(value) > 253:
        raise ValueError("Invalid artifact-site domain")
    value = value.lower()
    labels = value.split(".")
    if len(labels) < 2 or not any("a" <= c <= "z" for c in labels[-1]):
        raise ValueError("A DNS domain is required")
    for label in labels:
        if not _as_re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ValueError("Invalid DNS label")
        if label.startswith("xn--"):
            try:
                if label.encode().decode("idna").encode("idna").decode() != label:
                    raise UnicodeError()
            except UnicodeError as exc:
                raise ValueError("Invalid Punycode label") from exc
    return value


def generate_artifact_profile(seed, theme="auto", title=None, description=None):
    """Create a v2 profile; auto selects only the four artifact-based families."""
    seed = _as_seed(seed)
    if theme not in ("auto", *ARTIFACT_THEMES):
        raise ValueError("Unknown artifact-site theme")
    theme = _as_pick(seed, "theme", ARTIFACT_THEMES) if theme == "auto" else theme
    data = _AS_CONTENT[theme]
    return {
        "version": 2, "seed": seed, "theme": theme,
        "title": _as_text(title if title is not None else _as_pick(seed, theme + ":title", data["names"]), "title", 160, True),
        "description": _as_text(description if description is not None else _as_pick(seed, theme + ":description", data["descriptions"]), "description", 1000, True),
        "layout": _as_pick(seed, theme + ":layout", _AS_LAYOUTS),
        "palette": _as_pick(seed, theme + ":palette", tuple(_AS_PALETTES)),
    }


def _as_profile(profile):
    if not isinstance(profile, dict) or set(profile) != _AS_KEYS:
        raise ValueError("Invalid artifact-site profile fields")
    if type(profile["version"]) is not int or profile["version"] != 2:
        raise ValueError("Unsupported artifact-site profile version")
    if profile["theme"] not in ARTIFACT_THEMES:
        raise ValueError("Artifact-site profile needs a concrete theme")
    _as_text(profile["title"], "title", 160)
    _as_text(profile["description"], "description", 1000)
    if profile != generate_artifact_profile(profile["seed"], profile["theme"], profile["title"], profile["description"]):
        raise ValueError("Artifact-site layout or palette disagrees with its seed")
    return dict(profile)


def _as_hex(hue, saturation, lightness):
    red, green, blue = _as_colorsys.hls_to_rgb((hue % 360) / 360, lightness / 100, saturation / 100)
    return "#" + "".join(f"{int(channel * 255 + 0.5):02X}" for channel in (red, green, blue))


def artifact_relative_luminance(color):
    """WCAG 2.2 sRGB luminance, from the exact exported eight-bit hex colour.

    Primary definition: https://www.w3.org/TR/WCAG22/#dfn-relative-luminance
    """
    if not isinstance(color, str) or not _as_re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
        raise ValueError("Expected a six-digit RGB hex colour")
    values = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in values]
    return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))


def artifact_contrast(first, second):
    high, low = sorted((artifact_relative_luminance(first), artifact_relative_luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _as_svg(width, height, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="study-title">\n'
            f'<title id="study-title">{_as_html.escape(title)}</title>\n' + "\n".join(body) + '\n</svg>\n')


def _as_spec(seed, kind, method):
    """Return source data and facts. Every public description uses these facts."""
    n = lambda label, low, high: _as_n(seed, label, low, high)
    hue = n("hue", 0, 359)
    colors = [_as_hex(hue, n("saturation", 35, 65), level) for level in (16, 38, 62, 88)]
    spec = {"kind": kind, "method": method, "canvas": {"width": 960, "height": 600}, "colors": colors, "parameters": {}, "primitives": []}
    params, primitives = spec["parameters"], spec["primitives"]
    if kind == "generative":
        if method == "circle-grid":
            columns, rows = n("columns", 5, 9), n("rows", 3, 5)
            params.update(columns=columns, rows=rows, margin=70, radius_min=10, radius_max=38)
            for row in range(rows):
                for column in range(columns):
                    primitives.append({"shape": "circle", "cx": 70 + column * 820 // (columns - 1), "cy": 70 + row * 460 // (rows - 1),
                                       "radius": n(f"radius:{row}:{column}", 10, 38), "color": colors[n(f"color:{row}:{column}", 0, 2)]})
            title = f"Circle field · {columns} × {rows}"
            summary = f"{len(primitives)} circles on a {columns}-column, {rows}-row grid. Radius and colour vary within the recorded bounds."
        elif method == "bar-field":
            count = n("bars", 9, 18)
            params.update(baseline=520, bars=count, gap=8)
            width = (820 - 8 * (count - 1)) // count
            for index in range(count):
                height = n(f"height:{index}", 100, 420)
                primitives.append({"shape": "rect", "x": 70 + index * (width + 8), "y": 520 - height,
                                   "width": width, "height": height, "color": colors[n(f"color:{index}", 0, 2)]})
            title = f"Bar rhythm · {count} elements"
            summary = f"{count} rectangles share a baseline at y=520. Their widths are {width} units; their individual heights are preserved in the JSON."
        else:
            count, step = n("frames", 7, 14), n("inset", 11, 16)
            params.update(frames=count, inset_step=step, stroke_width=n("stroke", 2, 5))
            for index in range(count):
                inset = 45 + index * step
                primitives.append({"shape": "frame", "x": inset, "y": inset, "width": 960 - 2 * inset,
                                   "height": 600 - 2 * inset, "color": colors[index % 3], "stroke_width": params["stroke_width"]})
            title = f"Nested frames · {count} steps"
            summary = f"{count} rectangular outlines are inset by {step} units per step, using a {params['stroke_width']}-unit stroke."
    elif kind == "patterns":
        tile = _as_pick(seed, "tile", (96, 128, 160))
        spec["canvas"] = {"width": tile, "height": tile}
        params.update(tile_width=tile, tile_height=tile)
        if method == "dot-grid":
            radius = n("radius", tile // 12, tile // 4)
            params.update(radius=radius)
            primitives.append({"shape": "circle", "cx": tile // 2, "cy": tile // 2, "radius": radius, "color": colors[1]})
            title = f"Dot repeat · {tile}-unit tile"
            summary = f"A centred circle with radius {radius} repeats on a {tile} × {tile} tile. The large preview repeats this exact tile."
        elif method == "diagonal-stripes":
            divisions = _as_pick(seed, "divisions", (4, 8))
            spacing = tile // divisions
            stroke = n("stroke", 2, max(2, spacing // 3))
            params.update(vertical_offset_interval=spacing, stroke_width=stroke, slope=1)
            for offset in range(-tile, tile + 1, spacing):
                primitives.append({"shape": "line", "x1": 0, "y1": offset, "x2": tile, "y2": offset + tile,
                                   "color": colors[1], "stroke_width": stroke})
            title = f"Diagonal repeat · {spacing}-unit interval"
            summary = f"Parallel 45-degree lines use vertical offsets of {spacing} units. That interval divides the {tile}-unit tile exactly, preserving the repeat across its edges."
        else:
            cells = 4
            step = tile // cells
            stroke = n("stroke", 2, max(2, step // 6))
            orientations = [[n(f"turn:{row}:{column}", 0, 1) for column in range(cells)] for row in range(cells)]
            params.update(columns=cells, rows=cells, cell_size=step, stroke_width=stroke, orientations=orientations)
            radius = step // 2
            for row in range(cells):
                for column in range(cells):
                    x, y = column * step, row * step
                    # Opposite corners need opposite sweep flags. This makes
                    # each arc cross its cell edge normally, so adjacent cells
                    # and copies of the complete tile join with equal tangents.
                    if orientations[row][column] == 0:
                        paths = (f"M{x+radius} {y}A{radius} {radius} 0 0 1 {x} {y+radius}", f"M{x+step} {y+radius}A{radius} {radius} 0 0 0 {x+radius} {y+step}")
                    else:
                        paths = (f"M{x} {y+radius}A{radius} {radius} 0 0 1 {x+radius} {y+step}", f"M{x+radius} {y}A{radius} {radius} 0 0 0 {x+step} {y+radius}")
                    for path in paths:
                        primitives.append({"shape": "path", "d": path, "color": colors[1], "stroke_width": stroke})
            title = f"Truchet repeat · {cells} × {cells} cells"
            summary = f"{cells*cells} cells contain {len(primitives)} quarter-circle arcs. Every arc meets a cell-edge midpoint; the JSON records all {cells*cells} orientations."
    elif kind == "palettes":
        base_hue, saturation = hue, n("palette-saturation", 35, 72)
        lightness = (15, 32, 50, 70, 90)
        if method == "analogous":
            step = n("hue-step", 9, 24)
            hues = [(base_hue + (index - 2) * step) % 360 for index in range(5)]
        elif method == "split-complementary":
            offset = n("split-offset", 22, 42)
            hues = [base_hue, (base_hue + 180 - offset) % 360, (base_hue + 180 + offset) % 360, base_hue, (base_hue + 180 - offset) % 360]
        else:
            hues = [base_hue] * 5
        hsl = [{"h": hue_value, "s": saturation, "l": level} for hue_value, level in zip(hues, lightness)]
        colors = [_as_hex(item["h"], item["s"], item["l"]) for item in hsl]
        spec["colors"] = colors
        params.update(hsl=hsl, hex=colors, contrast_matrix=[[round(artifact_contrast(first, second), 3) for second in colors] for first in colors])
        for index, color in enumerate(colors):
            primitives.append({"shape": "rect", "x": index * 192, "y": 0, "width": 192, "height": 600, "color": color})
        pairs = [(artifact_contrast(colors[i], colors[j]), i, j) for i in range(5) for j in range(i + 1, 5)]
        ratio, first, second = max(pairs)
        params["strongest_pair"] = {"first": colors[first], "second": colors[second], "ratio": round(ratio, 3)}
        title = method.replace("-", " ").title() + f" · hue {base_hue}°"
        summary = f"Five sRGB colours from explicit HSL steps. The strongest measured pair is {colors[first]} / {colors[second]} at {ratio:.2f}:1."
    else:
        p0, p3 = [75, 450], [885, 150]
        p1, p2 = [n("p1x", 130, 390), n("p1y", 60, 510)], [n("p2x", 550, 830), n("p2y", 60, 510)]
        paths = [[p0, p1, p2, p3]]
        if method == "mirrored-pair":
            paths.append([[960 - x, y] for x, y in paths[0]])
        elif method == "curve-bundle":
            paths = [[p0, [n(f"p1x:{index}", 130, 420), n(f"p1y:{index}", 60, 520)],
                      [n(f"p2x:{index}", 540, 830), n(f"p2y:{index}", 60, 520)], p3] for index in range(n("curves", 5, 9))]
        stroke = n("curve-stroke", 3, 6)
        params.update(control_points=paths, stroke_width=stroke, curve_count=len(paths))
        for index, points in enumerate(paths):
            a, b, c, d = points
            primitives.append({"shape": "path", "d": f"M{a[0]} {a[1]}C{b[0]} {b[1]} {c[0]} {c[1]} {d[0]} {d[1]}",
                               "color": colors[index % 3], "stroke_width": stroke})
        title = method.replace("-", " ").title() + f" · {len(paths)} path" + ("s" if len(paths) != 1 else "")
        summary = f"{len(paths)} cubic Bezier path" + ("s" if len(paths) != 1 else "") + f" with a {stroke}-unit stroke. All four control points for every path are included in the downloadable data."
    return spec, title, summary


def _as_draw(spec):
    width, height = spec["canvas"]["width"], spec["canvas"]["height"]
    body = [f'<rect width="{width}" height="{height}" fill="{spec["colors"][-1]}"/>']
    for item in spec["primitives"]:
        shape = item["shape"]
        if shape == "circle":
            body.append(f'<circle cx="{item["cx"]}" cy="{item["cy"]}" r="{item["radius"]}" fill="{item["color"]}"/>')
        elif shape in ("rect", "frame"):
            style = f'fill="{item["color"]}"' if shape == "rect" else f'fill="none" stroke="{item["color"]}" stroke-width="{item["stroke_width"]}"'
            body.append(f'<rect x="{item["x"]}" y="{item["y"]}" width="{item["width"]}" height="{item["height"]}" {style}/>')
        elif shape == "line":
            body.append(f'<line x1="{item["x1"]}" y1="{item["y1"]}" x2="{item["x2"]}" y2="{item["y2"]}" stroke="{item["color"]}" stroke-width="{item["stroke_width"]}"/>')
        else:
            body.append(f'<path d="{item["d"]}" fill="none" stroke="{item["color"]}" stroke-width="{item["stroke_width"]}"/>')
    if spec["kind"] == "palettes":
        for index, color in enumerate(spec["colors"]):
            label_color = "#FFFFFF" if artifact_contrast(color, "#FFFFFF") >= artifact_contrast(color, "#000000") else "#000000"
            body.append(f'<text x="{index*192+96}" y="540" text-anchor="middle" font-family="monospace" font-size="22" fill="{label_color}">{color}</text>')
    return body


def build_artifact_collection(profile):
    """Return the actual public artifacts, with text/data/assets kept together."""
    profile = _as_profile(profile)
    seed, theme = profile["seed"], profile["theme"]
    methods = sorted(_AS_CONTENT[theme]["methods"], key=lambda method: _as_digest(seed, "method-order:" + method))
    count = _as_n(seed, "collection-size", 3, 5)
    collection = []
    for index in range(count):
        spec, title, summary = _as_spec(_as_digest(seed, f"object:{index}"), theme, methods[index % len(methods)])
        identity = _as_hashlib.sha256(_as_json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]
        stem = f"study-{index+1:02d}-{identity}"
        svg_name, css_name, json_name = ("downloads/" + stem + extension for extension in (".svg", ".css", ".json"))
        body = _as_draw(spec)
        width, height = spec["canvas"]["width"], spec["canvas"]["height"]
        svg = _as_svg(width, height, body, title)
        css = ":root {\n" + "".join(f"  --study-color-{number}: {color};\n" for number, color in enumerate(spec["colors"], 1)) + "}\n"
        if theme == "patterns":
            css += (f".study-pattern {{\n  background-image: url('./{stem}.svg');\n  background-repeat: repeat;\n"
                    f"  background-size: {width}px {height}px;\n}}\n")
            preview_body = [f'<defs><pattern id="tile" width="{width}" height="{height}" patternUnits="userSpaceOnUse">', *body, '</pattern></defs>',
                            '<rect width="960" height="600" fill="url(#tile)"/>']
            preview = _as_svg(960, 600, preview_body, title + " — repeated field")
        else:
            css += (f".study-artwork {{\n  background-image: url('./{stem}.svg');\n  background-repeat: no-repeat;\n"
                    f"  background-size: contain;\n  aspect-ratio: {width} / {height};\n}}\n")
            preview = svg
        data = {**spec, "title": title, "description": summary,
                "files": {"svg": svg_name.rsplit("/", 1)[-1], "css": css_name.rsplit("/", 1)[-1]},
                "svg_sha256": _as_hashlib.sha256(svg.encode()).hexdigest()}
        collection.append({"id": stem, "title": title, "summary": summary, "spec": spec,
                           "page": "studies/" + stem + ".html", "preview": "assets/" + stem + ".svg",
                           "svg_name": svg_name, "css_name": css_name, "json_name": json_name,
                           "svg": svg, "css": css, "json": _as_json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                           "preview_svg": preview})
    return collection


_AS_CSS = r'''
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.75 Georgia,'Times New Roman',serif}a{color:inherit;text-underline-offset:4px}a:hover{color:var(--accent)}a:focus-visible{outline:2px solid var(--accent);outline-offset:5px}img{display:block;width:100%;height:auto}.shell{max-width:1220px;margin:auto;padding:0 40px}header{display:flex;justify-content:space-between;align-items:center;gap:25px;border-bottom:1px solid var(--border);padding:28px 0}.brand{display:flex;align-items:center;gap:12px;text-decoration:none;font-size:18px;font-weight:bold}.brand img{width:30px;height:30px}.brand span{overflow-wrap:anywhere}nav{display:flex;gap:22px;font:12px/1.5 Arial,sans-serif;flex-shrink:0}nav a{text-decoration:none}nav a[aria-current=page]{text-decoration:underline}.eyebrow,.number,.method-label{font:11px/1.5 'Courier New',monospace;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}h1,h2,h3{font-weight:400;line-height:1.15;letter-spacing:-.025em;overflow-wrap:anywhere}h1{font-size:clamp(38px,6vw,72px);margin:18px 0 25px}h2{font-size:26px;margin:16px 0}h3{font-size:22px}.lead{color:var(--muted);font-size:20px;max-width:760px}.summary{color:var(--muted);font-size:15px}.intro{padding:55px 0 40px}.artwork{display:block;overflow:hidden;background:var(--panel);border:1px solid var(--border)}.artwork img{aspect-ratio:8/5;object-fit:cover}.object-title{text-decoration:none}.download-links{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0;font:12px/1.5 Arial,sans-serif}.download-links a{padding:8px 12px;border:1px solid var(--border);text-decoration:none;background:var(--panel)}.study-page,.text-page{max-width:850px;margin:60px auto 75px}.study-page h1,.text-page h1{font-size:clamp(34px,5vw,56px)}.study-page figure{margin:32px 0}.study-page figure img{border:1px solid var(--border)}figcaption{font:12px/1.6 Arial,sans-serif;color:var(--muted);margin-top:12px}table{width:100%;border-collapse:collapse;margin:25px 0;font:13px/1.6 Arial,sans-serif}th,td{text-align:left;border-bottom:1px solid var(--border);padding:10px 12px;vertical-align:top;overflow-wrap:anywhere}th{font-weight:600}code,pre{font-family:'Courier New',monospace;font-size:12px}pre{padding:20px;overflow:auto;background:var(--panel);line-height:1.6;border:1px solid var(--border)}.table-scroll{overflow:auto}.downloads-index li,.related li{margin:14px 0}.related{margin-top:40px;padding-top:20px;border-top:1px solid var(--border)}footer{display:flex;justify-content:space-between;gap:25px;flex-wrap:wrap;border-top:1px solid var(--border);margin-top:55px;padding:24px 0 35px;color:var(--muted);font:11px/1.6 Arial,sans-serif}.swatch{display:inline-block;width:18px;height:18px;border:1px solid var(--border);vertical-align:middle;margin-right:10px}.hero-split{display:grid;grid-template-columns:1fr 1fr;gap:50px;align-items:center;padding:60px 0}.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:40px 30px}.cards article{padding-bottom:20px}.cards .number{display:block;margin:15px 0}.catalog{list-style:none;padding:0;border-top:2px solid var(--fg)}.catalog li{display:grid;grid-template-columns:40px minmax(0,1fr) 200px;gap:25px;align-items:start;border-bottom:1px solid var(--border);padding:28px 0}.catalog h2{margin-top:5px}.catalog .number{padding-top:10px}.folio-row{display:grid;grid-template-columns:1.25fr 1fr;gap:60px;align-items:center;padding:48px 0;border-top:1px solid var(--border)}.folio-row:nth-child(even){direction:rtl}.folio-row>*{direction:ltr}.folio-row h2{font-size:32px}.notebook{display:grid;grid-template-columns:210px minmax(0,1fr);gap:45px}.notebook-toc{position:sticky;top:25px;align-self:start}.notebook-toc ol{padding-left:20px}.notebook-toc li{margin:14px 0;font-size:14px}.notebook-entry{background:var(--panel);padding:28px;border-left:3px solid var(--accent);margin-bottom:30px}.notebook-entry .artwork{max-width:440px;margin:22px 0}.bulletin-heading{text-align:center;border-bottom:3px double var(--fg);padding:48px 25px 35px}.bulletin-heading h1{font-weight:bold;font-size:clamp(45px,7vw,90px)}.bulletin-heading .lead{margin:20px auto}.bulletin-grid{display:grid;grid-template-columns:1.5fr 1fr;gap:40px;margin-top:35px}.bulletin-main{border-right:1px solid var(--border);padding-right:38px}.bulletin-column article{border-bottom:1px solid var(--border);padding:10px 0 25px}.bulletin-main h2{font-size:36px}.editorial-feature{display:grid;grid-template-columns:1.2fr 1fr;gap:40px;align-items:center;padding:35px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border);margin-bottom:35px}.editorial-rest{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:35px}.editorial-rest article{padding:20px 0;border-bottom:1px solid var(--border)}.layout-gallery .shell{display:grid;grid-template-columns:185px minmax(0,1fr);gap:0 45px;max-width:1400px}.layout-gallery header{display:block;grid-column:1;grid-row:1/3;border-bottom:0;border-right:1px solid var(--border);padding:32px 22px 0 0;align-self:start;position:sticky;top:0}.layout-gallery .brand{display:block;font-size:23px}.layout-gallery .brand img{margin-bottom:20px;width:40px;height:40px}.layout-gallery nav{display:flex;flex-direction:column;margin-top:35px;gap:18px}.layout-gallery main,.layout-gallery footer{grid-column:2}.layout-gallery h1{font-family:Arial,sans-serif;font-size:clamp(40px,6vw,75px)}.layout-index{font-family:Arial,sans-serif}.layout-index h1{font-size:clamp(36px,5vw,60px)}.layout-notebook h1{font-family:'Courier New',monospace;font-size:clamp(34px,4vw,52px)}.layout-folio .hero-split{grid-template-columns:1.15fr 1fr}.layout-folio .hero-split .artwork{aspect-ratio:4/5}.layout-folio .hero-split .artwork img{height:100%;object-fit:cover}
@media(max-width:800px){.shell{padding:0 24px}.hero-split{gap:30px}.catalog li{grid-template-columns:28px minmax(0,1fr) 140px;gap:18px}.folio-row{gap:30px}.notebook{grid-template-columns:160px minmax(0,1fr);gap:25px}.layout-gallery .shell{grid-template-columns:140px minmax(0,1fr);gap:0 25px}.layout-gallery .brand{font-size:19px}}
@media(max-width:600px){header{padding:22px 0;gap:15px}.brand{font-size:15px}nav{gap:14px;font-size:11px}.hero-split,.editorial-feature,.bulletin-grid,.folio-row{display:block}.hero-split .artwork{margin-top:25px}.cards,.editorial-rest{grid-template-columns:1fr}.catalog li{grid-template-columns:25px minmax(0,1fr)}.catalog .row-preview{display:none}.folio-row .artwork{margin-bottom:25px}.notebook{display:block}.notebook-toc{position:static}.notebook-toc ol{columns:2}.notebook-entry{padding:22px}.bulletin-main{border-right:0;border-bottom:1px solid var(--border);padding:0 0 28px}.bulletin-column{margin-top:25px}.layout-gallery .shell{display:block}.layout-gallery header{display:flex;position:static;border-right:0;border-bottom:1px solid var(--border);padding:22px 0}.layout-gallery .brand{display:flex;font-size:16px}.layout-gallery .brand img{width:26px;height:26px;margin:0}.layout-gallery nav{flex-direction:row;margin:0;gap:12px}.layout-folio .hero-split .artwork{aspect-ratio:8/5}.study-page,.text-page{margin:42px auto 50px}.lead{font-size:18px}th,td{padding:8px}.intro{padding-top:40px}}
'''


def render_artifact_site(domain, profile):
    """Return a complete site of real, downloadable SVG/CSS/JSON studies."""
    domain, profile = _as_domain(domain), _as_profile(profile)
    e = _as_html.escape
    seed, theme, layout = profile["seed"], profile["theme"], profile["layout"]
    content, colors = _AS_CONTENT[theme], _AS_PALETTES[profile["palette"]]
    formula_link = ('<p>The calculations follow the <a href="https://www.w3.org/TR/WCAG22/#dfn-relative-luminance">W3C definition of sRGB relative luminance</a>; the contrast ratio is (lighter luminance + 0.05) / (darker luminance + 0.05).</p>'
                    if theme == "palettes" else "")
    studies = build_artifact_collection(profile)
    css_name = "assets/site-" + _as_digest(seed, "stylesheet")[:16] + ".css"
    icon_name = "assets/icon-" + _as_digest(seed, "favicon")[:16] + ".svg"
    properties = "".join(f"--{name}:{color};" for name, color in zip(("bg", "fg", "muted", "accent", "panel", "border"), colors))
    files = {css_name: ":root{" + properties + "}\n" + _AS_CSS,
             icon_name: _as_svg(64, 64, [f'<rect width="64" height="64" rx="14" fill="{colors[3]}"/>',
                                       f'<circle cx="24" cy="25" r="10" fill="{colors[0]}"/><path d="M22 45L45 22V45Z" fill="{colors[0]}"/>'], content["eyebrow"])}

    def page(title, body, filename, active="", description=None):
        navigation = "".join(f'<a href="{url}"' + (' aria-current="page"' if active == key else '') + f'>{label}</a>'
                             for key, url, label in (("collection", "/", "Collection"), ("methods", "/methods.html", "Methods"), ("about", "/about.html", "About")))
        canonical = "https://" + domain + "/" + ("" if filename == "index.html" else filename)
        return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="{e(description if description is not None else profile['description'], quote=True)}">
<title>{e(title, quote=True)} · {e(profile['title'], quote=True)}</title><link rel="canonical" href="{canonical}">
<link rel="icon" type="image/svg+xml" href="/{icon_name}"><link rel="stylesheet" href="/{css_name}"></head>
<body class="layout-{layout} theme-{theme}"><div class="shell"><header><a class="brand" href="/"><img src="/{icon_name}" alt="" width="30" height="30"><span>{e(profile['title'], quote=True)}</span></a><nav aria-label="Main navigation">{navigation}</nav></header>
<main>{body}</main><footer><span>{domain}</span><span><a href="/downloads.html">Download the studies</a> · SVG / CSS / JSON</span></footer></div></body></html>
'''

    def preview(item, cls="artwork"):
        return f'<a class="{cls}" href="/{item["page"]}"><img src="/{item["preview"]}" alt="{e(item["title"], quote=True)}" width="960" height="600" loading="lazy"></a>'

    def text(item):
        return (f'<p class="method-label">{e(item["spec"]["method"].replace("-", " "))}</p><h2><a class="object-title" href="/{item["page"]}">{e(item["title"])}</a></h2>'
                f'<p class="summary">{e(item["summary"])}</p><a href="/{item["page"]}">Inspect the study</a>')

    intro = f'<p class="eyebrow">{e(content["eyebrow"])}</p><h1>{e(profile["title"])}</h1><p class="lead">{e(profile["description"])}</p>'
    if layout == "gallery":
        cards = "".join(f'<article><span class="number">Study {index:02d}</span>{preview(item)}{text(item)}</article>' for index, item in enumerate(studies, 1))
        home = f'<section class="intro">{intro}</section><section class="cards" aria-label="The collection">{cards}</section>'
    elif layout == "index":
        rows = "".join(f'<li><span class="number">{index:02d}</span><div>{text(item)}</div>{preview(item,"row-preview")}</li>' for index, item in enumerate(studies, 1))
        home = f'<section class="intro">{intro}</section><ol class="catalog">{rows}</ol>'
    elif layout == "folio":
        rows = "".join(f'<article class="folio-row">{preview(item)}<div><p class="number">{index:02d} / {len(studies):02d}</p>{text(item)}</div></article>' for index, item in enumerate(studies, 1))
        home = f'<section class="hero-split">{preview(studies[0])}<div>{intro}</div></section><section aria-label="The collection">{rows}</section>'
    elif layout == "notebook":
        toc = "".join(f'<li><a href="#study-{index}">{e(item["title"])}</a></li>' for index, item in enumerate(studies, 1))
        entries = "".join(f'<article class="notebook-entry" id="study-{index}"><p class="number">Study {index:02d}</p>{text(item)}{preview(item)}<p class="summary">Source files: editable SVG, matching CSS, and the actual parameter JSON.</p></article>' for index, item in enumerate(studies, 1))
        home = f'<section class="intro">{intro}</section><div class="notebook"><aside class="notebook-toc"><p class="eyebrow">In this collection</p><ol>{toc}</ol></aside><section>{entries}</section></div>'
    elif layout == "bulletin":
        column = "".join(f'<article>{text(item)}</article>' for item in studies[1:])
        home = f'<section class="bulletin-heading">{intro}</section><section class="bulletin-grid"><article class="bulletin-main">{preview(studies[0])}{text(studies[0])}</article><div class="bulletin-column">{column}</div></section>'
    else:
        rest = "".join(f'<article>{text(item)}</article>' for item in studies[1:])
        home = f'<section class="intro">{intro}</section><article class="editorial-feature">{preview(studies[0])}<div>{text(studies[0])}</div></article><section class="editorial-rest" aria-label="More studies">{rest}</section>'
    files["index.html"] = page("Collection", home, "index.html", "collection")

    def downloads(item):
        return '<div class="download-links">' + "".join(f'<a download href="/{item[key]}">Download {label}</a>' for key, label in (("svg_name", "SVG"), ("css_name", "CSS"), ("json_name", "JSON"))) + '</div>'

    for item in studies:
        files.update({item["svg_name"]: item["svg"], item["css_name"]: item["css"], item["json_name"]: item["json"], item["preview"]: item["preview_svg"]})
        spec = item["spec"]
        rows = [("Construction", spec["method"].replace("-", " ")), ("SVG dimensions", f'{spec["canvas"]["width"]} × {spec["canvas"]["height"]}'),
                ("Geometric primitives", str(len(spec["primitives"]))), ("Colours", ", ".join(spec["colors"]))]
        table = '<table><tbody>' + "".join(f'<tr><th>{e(label)}</th><td>{e(value)}</td></tr>' for label, value in rows) + '</tbody></table>'
        detail = ""
        if theme == "palettes":
            matrix = spec["parameters"]["contrast_matrix"]
            table_head = '<tr><th>Pair</th>' + "".join(f'<th>{e(color)}</th>' for color in spec["colors"]) + '</tr>'
            table_rows = "".join('<tr><th>' + e(color) + '</th>' + "".join(f'<td>{ratio:.2f}:1</td>' for ratio in matrix[index]) + '</tr>' for index, color in enumerate(spec["colors"]))
            detail = '<h2>Measured contrast pairs</h2><div class="table-scroll"><table>' + table_head + table_rows + '</table></div><p>Ratios use the exact exported sRGB hex values. They describe these pairs, not the accessibility of an entire interface.</p>'
        params = _as_json.dumps(spec["parameters"], ensure_ascii=False, indent=2)
        related = "".join(f'<li><a href="/{other["page"]}">{e(other["title"])}</a></li>' for other in studies if other is not item)
        caption = "The repeated field uses the exact downloadable tile." if theme == "patterns" else "This preview uses the exact downloadable SVG."
        body = (f'<article class="study-page"><p class="eyebrow">{e(spec["method"].replace("-", " "))}</p><h1>{e(item["title"])}</h1><p class="lead">{e(item["summary"])}</p>'
                f'<figure><img src="/{item["preview"]}" alt="{e(item["title"], quote=True)}" width="960" height="600"><figcaption>{caption}</figcaption></figure>'
                f'{downloads(item)}<h2>What is in this study</h2>{table}<p>{e(content["method_text"])}</p>{detail}{formula_link}'
                f'<h2>The actual parameters</h2><pre>{e(params)}</pre><p>The JSON download also records every geometric primitive and the SHA-256 of the SVG file.</p>'
                f'<h2>Make a variation</h2><p>{e(content["editing"])}</p>'
                '<p>Keep the SVG and CSS in the same directory when using the background-image rule. The CSS also exports the colours as custom properties.</p>'
                f'<section class="related"><h2>Other studies</h2><ul>{related}</ul></section></article>')
        files[item["page"]] = page(item["title"], body, item["page"], description=item["summary"])
    files["methods.html"] = page("Methods", f'<article class="text-page"><p class="eyebrow">How the materials are made</p><h1>From parameters to a usable file</h1><p class="lead">{e(content["method_text"])}</p>{formula_link}<h2>One source for image and description</h2><p>Each study begins with a bounded set of parameters. Those values produce its SVG, its downloadable JSON, and the measurements stated on its page. Compare the image with its numbers to see how individual choices affect the composition.</p><h2>Three useful formats</h2><p>SVG contains editable vector geometry. CSS provides colour variables and a local background-image rule. JSON preserves the parameters, primitives and SVG checksum. Download the SVG and CSS into the same directory, then include the stylesheet in your project.</p><h2>Make a variation</h2><p>{e(content["editing"])}</p><p><a href="/downloads.html">Browse the available downloads</a></p></article>', "methods.html", "methods")
    files["about.html"] = page("About", f'<article class="text-page"><p class="eyebrow">About the collection</p><h1>{e(profile["title"])}</h1><p class="lead">{e(content["about"])}</p><h2>Explore, compare, and adapt</h2><p>The collection contains {len(studies)} original parameter-based studies. Each page pairs the finished image with its dimensions, construction data, and source files. Open two studies to compare their proportions or colour choices, then download a starting point for your own variation.</p><h2>Take a study into your project</h2><p>{e(content["editing"])}</p><p><a href="/methods.html">Read about the construction methods</a> or <a href="/downloads.html">browse the available files</a>.</p></article>', "about.html", "about")
    download_entries = "".join(f'<li><h2><a href="/{item["page"]}">{e(item["title"])}</a></h2><p class="summary">{e(item["summary"])}</p>{downloads(item)}</li>' for item in studies)
    files["downloads.html"] = page("Downloads", f'<section class="text-page"><p class="eyebrow">Usable source files</p><h1>Download the studies</h1><p class="lead">Every link below points to a real local file. Keep matching SVG and CSS files together to use the supplied background rule.</p><ul class="downloads-index">{download_entries}</ul></section>', "downloads.html")
    files["404.html"] = page("Page not found", '<section class="text-page"><p class="eyebrow">404</p><h1>Page not found</h1><p>The address may have changed.</p><p><a href="/">Return to the collection</a></p></section>', "404.html")
    pages = ["", "about.html", "methods.html", "downloads.html"] + [item["page"] for item in studies]
    files["sitemap.xml"] = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "".join(f'  <url><loc>https://{domain}/{name}</loc></url>\n' for name in pages) + '</urlset>\n'
    files["robots.txt"] = f"User-agent: *\nAllow: /\nSitemap: https://{domain}/sitemap.xml\n"
    for name, value in files.items():
        path = _ASPath(name)
        if path.is_absolute() or str(path) != name or ".." in path.parts or not _as_re.fullmatch(r"[a-z0-9][a-z0-9_./-]*", name) or not isinstance(value, str):
            raise ValueError("Invalid generated artifact file")
    return files
