"""Integrity pins for the vendored admin-panel assets.

The files under omlx/admin/static/js and /css are third-party code that
executes in the admin panel. They are fetched from public CDNs by
vendor_deps.py, so a hijacked CDN path or an edited checkout would
otherwise land a payload in the panel with nothing to catch it.

These tests fail if a vendored file drifts from the hash pinned in
vendor_deps.INTEGRITY. A legitimate version bump updates the URL and
re-pins with `--update-hashes`; anything else is worth reading before
trusting.
"""

import pytest

from omlx.admin.vendor_deps import (
    CSS_DEPS,
    INTEGRITY,
    JS_DEPS,
    STATIC,
    IntegrityError,
    _sha256,
    _verify,
)


@pytest.mark.parametrize("dest_rel", sorted(INTEGRITY))
def test_vendored_file_matches_pin(dest_rel):
    path = STATIC / dest_rel
    assert path.exists(), f"{dest_rel} is pinned but missing from static/"
    _verify(dest_rel, path)


def test_every_js_and_css_dep_is_pinned():
    """A new dependency must arrive with a hash, not slip in unpinned."""
    unpinned = sorted((JS_DEPS | CSS_DEPS).keys() - INTEGRITY.keys())
    assert not unpinned, (
        f"these dependencies have no integrity pin: {unpinned}. "
        "Add them to INTEGRITY (see --update-hashes)."
    )


def test_no_stale_pins():
    """A pin left behind after a dependency is dropped is dead weight."""
    stale = sorted(INTEGRITY.keys() - (JS_DEPS | CSS_DEPS).keys())
    assert not stale, f"INTEGRITY pins files no longer downloaded: {stale}"


def test_pins_are_well_formed_sha256():
    for dest_rel, digest in INTEGRITY.items():
        assert len(digest) == 64, f"{dest_rel}: not a sha256 digest"
        assert set(digest) <= set("0123456789abcdef"), (
            f"{dest_rel}: digest must be lowercase hex"
        )


def test_verify_rejects_modified_content(tmp_path):
    """The check has to actually fail on a byte change, not just pass."""
    dest_rel = next(iter(INTEGRITY))
    original = (STATIC / dest_rel).read_bytes()

    tampered = tmp_path / "tampered.js"
    tampered.write_bytes(original + b"\n/* injected */\n")
    assert _sha256(tampered) != INTEGRITY[dest_rel]

    with pytest.raises(IntegrityError):
        _verify(dest_rel, tampered)


def test_unpinned_path_is_not_checked(tmp_path):
    """Fonts and other unpinned files pass through without a hash."""
    anything = tmp_path / "font.woff2"
    anything.write_bytes(b"not pinned")
    _verify("fonts/inter/inter-latin-400-normal.woff2", anything)
