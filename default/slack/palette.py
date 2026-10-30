"""Slack CSS palette, adapted from GruperTal/omarchy-slack-theme (MIT).

Copyright (c) 2026 GruperTal. See LICENSE beside this file.
"""

import re

HEX = re.compile(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})")

# Slack palette -> Omarchy colour, picked by the hue of Slack's own shade 50.
# aubergine is Slack's brand/sidebar default, so it takes the accent.
PALETTES = {
    "tomato": "red", "paprika": "red", "rose": "red",
    "tangerine": "orange", "campfire": "orange", "horchata": "orange",
    "honeycomb": "yellow", "sunflower": "yellow",
    "grass": "green", "cilantro": "green", "mojito": "green", "jade": "green",
    "aquarium": "cyan", "lagoon": "cyan",
    "ocean": "blue", "indigo": "blue",
    "aubergine": "accent", "sangria": "magenta", "flamingo": "magenta",
    "primary": "accent", "important": "red",
}
SHADES = (0, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100)


def rgb(h):
    h = h.lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def mix(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def luminance(c):
    ch = [v / 255 for v in c]
    ch = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in ch]
    return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2]


def contrast(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def fit(c, against, toward, ratio=4.5):
    """Move c toward `toward` just far enough to reach `ratio` contrast with `against`."""
    for i in range(21):
        out = mix(c, toward, i / 20)
        if contrast(out, against) >= ratio:
            return out
    return toward


def hx(c, alpha=None):
    return "#%02x%02x%02x" % c + ("" if alpha is None else "%02x" % alpha)


def ramp(stops, s):
    for (s0, c0), (s1, c1) in zip(stops, stops[1:]):
        if s <= s1:
            return mix(c0, c1, (s - s0) / (s1 - s0))
    return stops[-1][1]


def build(t):
    if not isinstance(t, dict) or t.get("mode") not in ("dark", "light"):
        raise ValueError("expected a light or dark color palette")
    c = {k: rgb(v) for k, v in t.items() if isinstance(v, str) and HEX.fullmatch(v)}
    if "accent" not in c:
        c["accent"] = c["blue"]
    bg, fg, muted, accent = c["background"], c["foreground"], c["muted"], c["accent"]
    dbg, darker_bg, lbg = c["dark_background"], c["darker_background"], c["lighter_background"]
    dfg, bright_fg = c["dark_foreground"], c["bright_foreground"]
    fg_hover, fg_pressed = hx(fg, 0x14), hx(fg, 0x2E)

    v = {}  # token name (without --dt_color-) -> css value

    # Palette ramps: shade 0 sits on the background side, 100 on the foreground side (both modes).
    neutral = [(0, dbg), (5, bg), (20, lbg), (50, muted), (100, bright_fg)]
    for s in SHADES:
        v[f"plt-gray-{s}"] = "%d,%d,%d" % ramp(neutral, s)
    for name, key in PALETTES.items():
        col = c[key]
        for s in SHADES:
            v[f"plt-{name}-{s}"] = "%d,%d,%d" % ramp([(0, bg), (50, col), (100, bright_fg)], s)
    for name in ("gray", *PALETTES):
        v[f"plt-{name}-hover"], v[f"plt-{name}-pressed"] = fg_hover, fg_pressed

    # Semantic tokens.
    v.update({
        "base-pry": hx(bg), "base-sec": hx(bg), "base-ter": hx(lbg),
        "base-inv-pry": hx(lbg), "base-inv-sec": hx(lbg), "base-modal": hx(darker_bg, 0x99),
        "ctr-pry": hx(lbg), "ctr-sec": hx(lbg),
        "surf-pry": hx(fg, 0x0F), "surf-sec": hx(fg, 0x40), "surf-inv": hx(fg, 0x2E),
        "surf-ter": hx(fg, 0x14), "surf-inv-pry": hx(fg, 0x14),
        "surf-inv-sec": hx(fg, 0x2E), "surf-inv-ter": hx(fg, 0x0F),
        "surf-inv-hgl-3": hx(c["yellow"], 0x2E),
        "content-pry": hx(fg), "content-sec": hx(fit(dfg, bg, fg)), "content-ter": hx(fit(muted, bg, fg)),
        "content-inv-pry": hx(fg), "content-inv-sec": hx(fit(dfg, bg, fg)),
        "content-inv-ter": hx(fit(muted, bg, fg)),
        "otl-pry": hx(muted), "otl-sec": hx(muted, 0x80), "otl-ter": hx(muted, 0x4D),
        "otl-inv-pry": hx(muted), "otl-inv-sec": hx(muted, 0x80), "otl-inv-ter": hx(muted, 0x4D),
    })
    roles = {"hgl-1": accent, "hgl-2": c["green"], "hgl-3": c["yellow"], "imp": c["red"], "education": c["magenta"]}
    for role, col in roles.items():
        text = hx(fit(col, bg, fg))
        v[f"base-{role}"] = hx(mix(bg, col, 0.15))
        v[f"base-inv-{role}"] = hx(fit(col, fg, bg))  # filled buttons carry content-inv-pry (fg) text
        v[f"content-{role}"] = v[f"content-inv-{role}"] = text
        v[f"surf-{role}"] = hx(col, 0x40)
        v[f"otl-{role}"] = text
        v[f"otl-{role}-sec"] = hx(col, 0x40)
    for k in [k for k in v if k.split("-")[0] in ("base", "surf", "ctr")]:
        v[f"{k}-hover"], v[f"{k}-pressed"] = fg_hover, fg_pressed

    link = fit(accent, bg, fg)
    solid = {"max": 0.7, "high": 0.46, "mid": 0.25, "low": 0.12, "soft": 0.05, "min": 0.04}
    sk = {
        "primary_foreground": fg, "primary_background": bg,
        "inverted_foreground": bg, "inverted_background": fg,
        "highlight": link, "highlight_hover": mix(link, fg, 0.25), "highlight_accent": link,
        "secondary_highlight": c["yellow"],
        **{f"foreground_{k}": fg for k in solid},
        **{f"foreground_{k}_solid": mix(bg, fg, x) for k, x in solid.items()},
    }

    decls = [f"  color-scheme: {t['mode']} !important;"]
    decls += [f"  --dt_color-{k}: {val} !important;" for k, val in v.items()]
    # Custom Slack themes publish literal theme-* tokens, so remapping the
    # palette ramps alone leaves their sidebar colours and text behind.
    decls += [f"  --dt_color-theme-{k}: {val} !important;" for k, val in v.items() if not k.startswith("plt-")]
    decls += [f"  --sk_{k}: %d, %d, %d !important;" % val for k, val in sk.items()]
    sel = ":root, body, .sk-client-theme--dark, .sk-client-theme--light, .sk-client-theme--light-inverted-sidebar, .p-client_workspace_wrapper"
    # Slack paints its inverted chrome over a separate accent-coloured layer.
    # Its header and workspace title are transparent, so their Omarchy text
    # needs the palette background beneath them too, including current ia4 UI.
    surfaces = "body, .p-theme_background, .p-tab_rail, .p-channel_sidebar, .p-top_nav, .p-ia4_top_nav, .p-view_contents--sidebar"
    return (f"/* Generated by Omarchy. */\n{sel} {{\n" + "\n".join(decls) + "\n}\n"
            + f"{surfaces} {{ background: {hx(bg)} !important; }}\n")
