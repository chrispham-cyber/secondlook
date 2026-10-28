"""International domain names: which alphabets an address uses and whether it is built to look like another.

Scammers register addresses such as "аррӏе.com" whose letters are all Cyrillic but look exactly like
"apple.com". Browsers and phones may show either the disguised form or its real "xn--" form. This
module turns any form into both, finds the alphabets in each part of the name, and builds a
"skeleton" (what the address looks like to a reader) so it can be compared with real company sites.

The look-alike table is a hand-picked subset of Unicode's confusables list (UTS #39) for the
alphabets most used in these attacks: Cyrillic, Greek, Armenian, and Latin letters with accents or
unusual shapes. Fullwidth and math-styled letters are folded by NFKC normalization.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Letters that look the same as a plain Latin letter in most fonts. Used to decide that a word written
# entirely in another alphabet is pretending to be Latin ("сосо" in Cyrillic reads as "coco").
STRONG: dict[str, str] = {
    # Cyrillic
    "а": "a", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "ӏ": "l", "о": "o",
    "р": "p", "ԛ": "q", "ѕ": "s", "ԝ": "w", "х": "x", "у": "y", "ү": "y", "ɡ": "g",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "υ": "u", "χ": "x", "ϲ": "c", "ϳ": "j",
    # Armenian
    "օ": "o", "ս": "u", "ո": "n", "հ": "h", "ց": "g", "զ": "q",
    # Latin letters with unusual shapes
    "ı": "i", "ɩ": "i", "ɪ": "i", "ɑ": "a", "ʋ": "u", "ʏ": "y", "ɴ": "n", "ʀ": "r", "ʜ": "h", "ʟ": "l",
}  # fmt: skip

# Letters that resemble a Latin letter closely enough to fool a quick read, especially in small type.
# Only used when comparing against company names, where a match is never an accident.
WEAK: dict[str, str] = {
    # Cyrillic
    "в": "b", "ь": "b", "г": "r", "к": "k", "м": "m", "н": "h", "п": "n", "т": "t", "ш": "w", "щ": "w",
    "ѵ": "v", "ё": "e", "ї": "i", "љ": "jb", "ц": "u", "и": "u", "л": "n", "я": "r", "з": "3", "б": "6",
    # Greek
    "ε": "e", "τ": "t", "η": "n", "μ": "u", "ω": "w", "β": "b", "γ": "y", "λ": "a", "δ": "d", "ς": "c",
    # Armenian
    "ա": "w", "ճ": "a", "ք": "p", "ռ": "n",
}  # fmt: skip

# Invisible characters that some software drops from addresses, so "pay­pal" can open "paypal".
INVISIBLE = {"­", "​", "‌", "‍", "⁠", "﻿", "͏", "᠎"}

# Mixes that are normal in one language and therefore not suspicious on their own (UTS #39
# "highly restrictive"): Japanese, Chinese, and Korean names can contain Latin and Han together.
_ALLOWED_MIXES = (
    {"Latin", "Han", "Hiragana", "Katakana"},
    {"Latin", "Han", "Bopomofo"},
    {"Latin", "Han", "Hangul"},
)

_SCRIPT_BY_NAME = {
    "LATIN": "Latin",
    "CYRILLIC": "Cyrillic",
    "GREEK": "Greek",
    "ARMENIAN": "Armenian",
    "GEORGIAN": "Georgian",
    "CHEROKEE": "Cherokee",
    "HEBREW": "Hebrew",
    "ARABIC": "Arabic",
    "CJK": "Han",
    "HIRAGANA": "Hiragana",
    "KATAKANA": "Katakana",
    "BOPOMOFO": "Bopomofo",
    "HANGUL": "Hangul",
    "THAI": "Thai",
    "DEVANAGARI": "Devanagari",
    "BENGALI": "Bengali",
    "TAMIL": "Tamil",
    "ETHIOPIC": "Ethiopic",
}


def script_of(ch: str) -> str:
    """The alphabet a character belongs to, or "Common" for digits and hyphens."""
    if ch.isascii():
        return "Latin" if ch.isalpha() else "Common"
    if unicodedata.category(ch).startswith("M"):
        return "Common"  # accents and other marks join the letter before them
    name = unicodedata.name(ch, "")
    first = name.split(" ", 1)[0]
    if first in ("MODIFIER", "SMALL") and "LATIN" in name:
        return "Latin"
    return _SCRIPT_BY_NAME.get(first, "Other")


def label_to_unicode(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return label
    return label


def label_to_ascii(label: str) -> str:
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError:
        return label


@dataclass
class HostForms:
    unicode: str  # what a person may see: "аррӏе.com"
    ascii: str  # what the computer actually visits: "xn--80ak6aa92e.com"
    skeleton: str  # what it looks like: "apple.com"
    scripts: list[str]  # alphabets used, in order of first appearance
    mixed_labels: list[tuple[str, list[str]]]  # parts of the name that mix alphabets
    hidden_characters: bool
    pretend_latin: list[str]  # parts written in another alphabet entirely from Latin look-alikes

    @property
    def international(self) -> bool:
        return self.unicode != self.ascii


def _fold(label: str) -> str:
    """NFKC (fullwidth and math letters), lowercase, and drop invisible characters."""
    label = "".join(ch for ch in label if ch not in INVISIBLE)
    return unicodedata.normalize("NFKC", label).lower()


def skeleton_label(label: str) -> str:
    """What the label looks like in plain Latin letters: accents removed, look-alikes swapped."""
    out = []
    for ch in unicodedata.normalize("NFD", _fold(label)):
        if unicodedata.category(ch).startswith("M"):
            continue  # é -> e
        out.append(STRONG.get(ch) or WEAK.get(ch) or ch)
    return "".join(out)


def analyze_host(host: str) -> HostForms:
    raw_labels = host.split(".")
    hidden = any(ch in INVISIBLE for ch in host)
    labels = [_fold(label_to_unicode(label)) for label in raw_labels]
    scripts: list[str] = []
    mixed: list[tuple[str, list[str]]] = []
    pretend: list[str] = []
    for label in labels:
        seen: list[str] = []
        for ch in label:
            s = script_of(ch)
            if s not in ("Common", "Other") and s not in seen:
                seen.append(s)
        scripts += [s for s in seen if s not in scripts]
        if len(seen) > 1 and not any(set(seen) <= allowed for allowed in _ALLOWED_MIXES):
            mixed.append((label, seen))
        letters = [ch for ch in label if ch.isalpha()]
        if seen and "Latin" not in seen and letters and all(ch in STRONG for ch in letters):
            pretend.append(label)
    return HostForms(
        unicode=".".join(labels),
        ascii=".".join(label_to_ascii(label) for label in labels),
        skeleton=".".join(skeleton_label(label) for label in labels),
        scripts=scripts,
        mixed_labels=mixed,
        hidden_characters=hidden,
        pretend_latin=pretend,
    )
