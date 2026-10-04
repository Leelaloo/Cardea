"""SVG score badge generator for Cardea.

Renders a self-contained shields.io-style flat badge (no network fonts, no
external assets) so it works on any marketplace/README. Output: --badge FILE.
"""

BAND_COLORS = {
    "EXCELLENT": "#2ea44f",
    "GOOD": "#0969da",
    "NEEDS WORK": "#dfaa1e",
    "BROKEN / RISKY": "#d73a49",
}

FONT = "font-family='DejaVu Sans,Verdana,Geneva,sans-serif' font-size='11'"


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def _text_width(s):
    # Verdana ~6.6px/char at 11px for mixed case; tuned for score strings
    return int(len(s) * 6.6) + 12


def render_badge(score, band_label, do_not_install=False):
    """Return SVG string for the badge."""
    value = f"{score}/100 · {band_label}" if not do_not_install else f"{score}/100 · DO NOT INSTALL"
    color = "#d73a49" if do_not_install else BAND_COLORS.get(band_label, "#d73a49")
    label = "Scanned by Cardea"
    lw, vw = _text_width(label), _text_width(value)
    w = lw + vw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" viewBox="0 0 {w} 20" role="img" '
        f'aria-label="{_esc(label)}: {_esc(value)}">'
        f'<title>{_esc(label)}: {_esc(value)}</title>'
        f'<linearGradient id="cardea-grad-{score}" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="cardea-clip-{score}"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#cardea-clip-{score})"><rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        f'<rect width="{w}" height="20" fill="url(#cardea-grad-{score})"/></g>'
        f'<g fill="#fff" text-anchor="middle" {FONT}>'
        f'<text x="{lw // 2}" y="15">{_esc(label)}</text>'
        f'<text x="{lw + vw // 2}" y="15">{_esc(value)}</text></g></svg>'
    )


def write_badge(report, path):
    """Write the SVG badge for a doctor JSON report. Returns the path."""
    svg = render_badge(report["score"], report["band"], report["do_not_install"])
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(svg)
    return path
