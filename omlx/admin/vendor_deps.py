#!/usr/bin/env python3
"""Download vendored dependencies for offline admin panel.

All libraries use permissive licenses (MIT/ISC/BSD/OFL) that allow bundling.
Run this script to download/update all CDN dependencies to static/.

Every JS and CSS dependency is pinned by sha256 in INTEGRITY below and
verified after download. These files execute in the admin panel, so a
compromised or hijacked CDN path must fail the build rather than land a
silent payload in static/. A version bump is therefore a two-step edit:
change the URL, then refresh the hash with --update-hashes and review the
diff.

Usage:
    python -m omlx.admin.vendor_deps              # download what's missing
    python -m omlx.admin.vendor_deps --verify     # re-check files on disk
    python -m omlx.admin.vendor_deps --update-hashes  # rewrite INTEGRITY
"""

import argparse
import hashlib
import re
import ssl
import sys
import urllib.request
from pathlib import Path

STATIC = Path(__file__).parent / "static"

# SSL context for HTTPS downloads
SSL_CTX = ssl.create_default_context()


class IntegrityError(RuntimeError):
    """A downloaded or on-disk vendored file did not match its pinned hash."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify(dest_rel: str, dest: Path) -> None:
    """Check dest against its pinned hash. No pin means no check."""
    expected = INTEGRITY.get(dest_rel)
    if expected is None:
        return
    actual = _sha256(dest)
    if actual != expected:
        raise IntegrityError(
            f"{dest_rel} failed its integrity check.\n"
            f"  expected sha256 {expected}\n"
            f"  actual   sha256 {actual}\n"
            "Upstream changed, the CDN served something unexpected, or the "
            "file was edited locally. Review the content before trusting it; "
            "if the change is intentional, re-pin with --update-hashes."
        )


def _download(
    url: str,
    dest: Path,
    description: str = "",
    optional: bool = False,
    dest_rel: str | None = None,
) -> bool:
    """Download a file from URL to destination path.

    Args:
        optional: If True, silently skip 404 errors (some font variants don't exist).
        dest_rel: Key into INTEGRITY. When set, the file is hash-verified
            both on the already-exists path and after a fresh download.

    Returns:
        True if downloaded or already exists, False if skipped.

    Raises:
        IntegrityError: the bytes do not match the pinned sha256.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        if dest_rel:
            _verify(dest_rel, dest)
        print(f"  [skip] {dest.name} (already exists)")
        return True
    label = description or dest.name
    print(f"  [download] {label} <- {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, context=SSL_CTX) as resp:
            dest.write_bytes(resp.read())
    except urllib.error.HTTPError as e:
        if optional and e.code == 404:
            print(f"  [skip] {dest.name} (not available)")
            return False
        raise
    if dest_rel:
        try:
            _verify(dest_rel, dest)
        except IntegrityError:
            # Never leave unverified bytes behind for the next run to
            # "[skip] (already exists)" straight past.
            dest.unlink(missing_ok=True)
            raise
    return True


# =========================================================================
# JavaScript dependencies
# =========================================================================
JS_DEPS = {
    # Alpine.js 3.14.8 (MIT)
    "js/alpine.min.js": "https://cdn.jsdelivr.net/npm/alpinejs@3.14.8/dist/cdn.min.js",
    # Lucide Icons 0.453.0 (ISC)
    "js/lucide.min.js": "https://unpkg.com/lucide@0.453.0/dist/umd/lucide.min.js",
    # Marked 12.0.0 (MIT)
    "js/marked.umd.js": "https://cdn.jsdelivr.net/npm/marked@12.0.0/lib/marked.umd.js",
    # marked-highlight 2.0.6 (MIT)
    "js/marked-highlight.umd.js": "https://cdn.jsdelivr.net/npm/marked-highlight@2.0.6/lib/index.umd.js",
    # Highlight.js 11.9.0 core (BSD-3-Clause)
    "js/highlight.min.js": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js",
    # Highlight.js language packs
    "js/hljs-python.min.js": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/python.min.js",
    "js/hljs-javascript.min.js": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/javascript.min.js",
    "js/hljs-bash.min.js": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/bash.min.js",
    "js/hljs-json.min.js": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/json.min.js",
    # KaTeX 0.16.9 (MIT)
    "js/katex.min.js": "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js",
    "js/katex-auto-render.min.js": "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/contrib/auto-render.min.js",
}

# =========================================================================
# CSS dependencies
# =========================================================================
CSS_DEPS = {
    # Highlight.js themes (BSD-3-Clause)
    "css/hljs-github.min.css": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css",
    "css/hljs-github-dark.min.css": "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css",
    # KaTeX CSS (MIT) - references fonts/ relative path
    "css/katex.min.css": "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css",
}


# =========================================================================
# Integrity pins
# =========================================================================
#
# sha256 of every JS/CSS dependency above, verified on download and by
# --verify. Each hash was confirmed against the upstream CDN at the time
# it was pinned. Regenerate with --update-hashes after a deliberate
# version bump, and review the resulting diff — an unexplained hash change
# is exactly the signal this map exists to catch.
#
# Fonts are not pinned: the Inter and CJK sources resolve through
# fontsource's `@latest`, which is not a fixed version, and woff2 files
# are not executable content.
INTEGRITY = {
    "js/alpine.min.js": "b600e363d99d95444db54acbfb2deffec9ae792aa99a09229bcda078e5b55643",
    "js/lucide.min.js": "b6df08e7a739c8f5b4ccccdbc453fc6d0c84003a96970ec5a583ee4627e6face",
    "js/marked.umd.js": "fc54fdd8854bc43ae2bc77d3a85e30f82fe629ece215eb39a2c3a94caa9dac2c",
    "js/marked-highlight.umd.js": "1b2491300a940d27d2e16fc0bc67fc1f70452ab6ef26b5f6640f8d00d79f6045",
    "js/highlight.min.js": "837a6fa5b0c736b52bbde2b2b6190f305da3fc9ed41681db5321507057b5c846",
    "js/hljs-python.min.js": "d49d8b48c93478ccd989b41da48f5fec4b0d1ebd986b5b764d18f0508e51ff6e",
    "js/hljs-javascript.min.js": "8f675eb100c79498bd35f422f9b5d7c36a4b89c729d7e47715506190792bf9f0",
    "js/hljs-bash.min.js": "fd9edcf3c6b2223b8987115f7799b1d1eec3000d045599cf4877c0f938ad8744",
    "js/hljs-json.min.js": "815cece9ac14999f064762fa9667ef86c55a67f017f00ed49ca9cdcb8c738778",
    "js/katex.min.js": "dc84b296ec3e884de093158f760fd9d45b6c7abe58b5381557f4e138f46a58ae",
    "js/katex-auto-render.min.js": "9cb8dacfc086c2966c9ec4ba54f4a2dc43b7cbe2b33cec1a2743d886c7fb47a7",
    "css/hljs-github.min.css": "3a9a5def8b9c311e5ae43abde85c63133185eed4f0d9f67fea4b00a8308cf066",
    "css/hljs-github-dark.min.css": "9f208d022102b1d0c7aebfecd8e42ca7997d5de636649d2b31ea63093d809019",
    "css/katex.min.css": "505d5f829022bb7b4f24dfee0aa1141cd7bba67afe411d1240335f820960b5c3",
}


def download_js_css() -> None:
    """Download JavaScript and CSS dependencies."""
    print("\n=== JavaScript Dependencies ===")
    for dest_rel, url in JS_DEPS.items():
        _download(url, STATIC / dest_rel, dest_rel=dest_rel)

    print("\n=== CSS Dependencies ===")
    for dest_rel, url in CSS_DEPS.items():
        _download(url, STATIC / dest_rel, dest_rel=dest_rel)


def verify_all() -> int:
    """Re-check every pinned file on disk. Returns a process exit code."""
    print("=== Verifying pinned vendored assets ===")
    missing, failed, ok = [], [], 0
    for dest_rel in INTEGRITY:
        path = STATIC / dest_rel
        if not path.exists():
            missing.append(dest_rel)
            print(f"  [missing] {dest_rel}")
            continue
        try:
            _verify(dest_rel, path)
        except IntegrityError as e:
            failed.append(dest_rel)
            print(f"  [FAIL] {e}")
        else:
            ok += 1
            print(f"  [ok] {dest_rel}")
    print(f"\n{ok} verified, {len(failed)} failed, {len(missing)} missing")
    return 1 if failed or missing else 0


def update_hashes() -> int:
    """Rewrite the INTEGRITY literal in this file from the files on disk."""
    source = Path(__file__)
    lines, missing = [], []
    for dest_rel in INTEGRITY:
        path = STATIC / dest_rel
        if not path.exists():
            missing.append(dest_rel)
            continue
        lines.append(f'    "{dest_rel}": "{_sha256(path)}",')
    if missing:
        print(f"error: cannot re-pin, files missing from static/: {missing}")
        return 1

    text = source.read_text(encoding="utf-8")
    start = text.index("INTEGRITY = {")
    end = text.index("}", start) + 1
    updated = text[:start] + "INTEGRITY = {\n" + "\n".join(lines) + "\n}" + text[end:]
    source.write_text(updated, encoding="utf-8")
    print(f"Re-pinned {len(lines)} hashes in {source.name}. Review the diff.")
    return 0


# =========================================================================
# KaTeX fonts
# =========================================================================
KATEX_VERSION = "0.16.9"
KATEX_FONT_BASE = f"https://cdn.jsdelivr.net/npm/katex@{KATEX_VERSION}/dist/fonts"

# All KaTeX font files referenced in katex.min.css
KATEX_FONTS = [
    "KaTeX_AMS-Regular",
    "KaTeX_Caligraphic-Bold",
    "KaTeX_Caligraphic-Regular",
    "KaTeX_Fraktur-Bold",
    "KaTeX_Fraktur-Regular",
    "KaTeX_Main-Bold",
    "KaTeX_Main-BoldItalic",
    "KaTeX_Main-Italic",
    "KaTeX_Main-Regular",
    "KaTeX_Math-BoldItalic",
    "KaTeX_Math-Italic",
    "KaTeX_SansSerif-Bold",
    "KaTeX_SansSerif-Italic",
    "KaTeX_SansSerif-Regular",
    "KaTeX_Script-Regular",
    "KaTeX_Size1-Regular",
    "KaTeX_Size2-Regular",
    "KaTeX_Size3-Regular",
    "KaTeX_Size4-Regular",
    "KaTeX_Typewriter-Regular",
]


def download_katex_fonts() -> None:
    """Download KaTeX font files (woff2 + ttf fallback)."""
    print("\n=== KaTeX Fonts ===")
    # Place in css/fonts/ so katex.min.css relative path works (url(fonts/...))
    fonts_dir = STATIC / "css" / "fonts"
    for font_name in KATEX_FONTS:
        for ext in ("woff2", "ttf"):
            url = f"{KATEX_FONT_BASE}/{font_name}.{ext}"
            _download(url, fonts_dir / f"{font_name}.{ext}", optional=True)


# =========================================================================
# Inter font (SIL Open Font License)
# =========================================================================
INTER_WEIGHTS = [300, 400, 500, 600, 700, 800]
INTER_FONT_BASE = "https://cdn.jsdelivr.net/fontsource/fonts/inter@latest"


def download_inter_fonts() -> None:
    """Download Inter font files and create @font-face CSS."""
    print("\n=== Inter Font ===")
    inter_dir = STATIC / "fonts" / "inter"
    inter_dir.mkdir(parents=True, exist_ok=True)

    for weight in INTER_WEIGHTS:
        url = f"{INTER_FONT_BASE}/latin-{weight}-normal.woff2"
        _download(url, inter_dir / f"inter-latin-{weight}-normal.woff2")

    # Generate @font-face CSS
    css_path = inter_dir / "inter.css"
    if css_path.exists():
        print("  [skip] inter.css (already exists)")
        return

    print("  [generate] inter.css")
    css_parts = []
    for weight in INTER_WEIGHTS:
        css_parts.append(f"""@font-face {{
  font-family: 'Inter';
  font-style: normal;
  font-weight: {weight};
  font-display: swap;
  src: url('./inter-latin-{weight}-normal.woff2') format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA,
    U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193,
    U+2212, U+2215, U+FEFF, U+FFFD;
}}""")
    css_path.write_text("\n\n".join(css_parts) + "\n")


# =========================================================================
# CJK fonts (SIL Open Font License)
# =========================================================================
CJK_FONTS = {
    # (font_family, fontsource_id, subset, dir_name, file_prefix)
    "noto-sans-sc": ("Noto Sans SC", "noto-sans-sc", "chinese-simplified", "NotoSansSC"),
    "noto-sans-tc": ("Noto Sans TC", "noto-sans-tc", "chinese-traditional", "NotoSansTC"),
    "noto-sans-kr": ("Noto Sans KR", "noto-sans-kr", "korean", "NotoSansKR"),
    "noto-sans-jp": ("Noto Sans JP", "noto-sans-jp", "japanese", "NotoSansJP"),
}
CJK_WEIGHTS = {400: "Regular", 500: "Medium", 700: "Bold"}
CJK_FONT_BASE = "https://cdn.jsdelivr.net/fontsource/fonts"


def download_cjk_fonts() -> None:
    """Download CJK font files (Noto Sans SC/TC/KR/JP) and create @font-face CSS."""
    print("\n=== CJK Fonts ===")
    for dir_name, (family, fontsource_id, subset, prefix) in CJK_FONTS.items():
        font_dir = STATIC / "fonts" / dir_name
        font_dir.mkdir(parents=True, exist_ok=True)

        for weight, weight_name in CJK_WEIGHTS.items():
            filename = f"{prefix}-{weight_name}.woff2"
            url = f"{CJK_FONT_BASE}/{fontsource_id}@latest/{subset}-{weight}-normal.woff2"
            _download(url, font_dir / filename)

        # Generate @font-face CSS
        css_path = font_dir / f"{dir_name}.css"
        if css_path.exists():
            print(f"  [skip] {dir_name}.css (already exists)")
            continue

        print(f"  [generate] {dir_name}.css")
        comment = {
            "noto-sans-sc": "Simplified Chinese",
            "noto-sans-tc": "Traditional Chinese",
            "noto-sans-kr": "Korean",
            "noto-sans-jp": "Japanese",
        }[dir_name]
        css_parts = [f"/* {family} - {comment} */"]
        for weight, weight_name in CJK_WEIGHTS.items():
            css_parts.append(f"""@font-face {{
  font-family: '{family}';
  font-style: normal;
  font-weight: {weight};
  font-display: swap;
  src: url('{prefix}-{weight_name}.woff2') format('woff2');
}}""")
        css_path.write_text("\n".join(css_parts) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Re-check the pinned files already in static/ and exit "
             "non-zero on any mismatch. Downloads nothing.",
    )
    parser.add_argument(
        "--update-hashes",
        action="store_true",
        help="Recompute INTEGRITY from the files in static/ and rewrite "
             "this file. Use after a deliberate version bump, then review "
             "the diff.",
    )
    args = parser.parse_args()

    if args.verify:
        return verify_all()
    if args.update_hashes:
        return update_hashes()

    print(f"Vendor directory: {STATIC}")
    try:
        download_js_css()
    except IntegrityError as e:
        print(f"\nerror: {e}", file=sys.stderr)
        return 1
    download_katex_fonts()
    download_inter_fonts()
    download_cjk_fonts()
    print("\n=== Done! ===")

    # Summary
    total = 0
    for p in STATIC.rglob("*"):
        if p.is_file() and p.suffix != ".svg":
            total += p.stat().st_size
    print(f"Total vendored size: {total / 1024 / 1024:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
