"""Upload validation. Every image is decoded and re-encoded, which strips EXIF/GPS metadata
and rejects files that only pretend to be images."""

from __future__ import annotations

import base64
import io

from PIL import Image, ImageOps, UnidentifiedImageError
from pillow_heif import register_heif_opener

register_heif_opener()  # iPhone photos (HEIC)

Image.MAX_IMAGE_PIXELS = 40_000_000  # decompression-bomb guard
MAX_LONG_SIDE = 1568  # larger images are downscaled by the API anyway
ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP", "GIF", "HEIF", "HEIC", "MPO"}


class ImageError(ValueError):
    pass


def prepare_image(data: bytes, max_bytes: int) -> tuple[str, str]:
    """Validate an upload and return (media_type, base64_data) ready for the API."""
    if len(data) > max_bytes:
        raise ImageError(f"Image is too large (max {max_bytes // 1_000_000} MB).")
    try:
        with Image.open(io.BytesIO(data)) as probe:
            fmt = (probe.format or "").upper()
            probe.verify()
        if fmt not in ALLOWED_FORMATS:
            raise ImageError("Unsupported image type. Use PNG, JPG, WEBP, or HEIC.")
        img = Image.open(io.BytesIO(data))
        img.seek(0)  # first frame of GIFs
        img = ImageOps.exif_transpose(img)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ImageError("That file doesn't look like a valid image.") from exc

    img = img.convert("RGB")
    img.thumbnail((MAX_LONG_SIDE, MAX_LONG_SIDE))
    out = io.BytesIO()
    img.save(out, format="PNG", optimize=True)  # fresh file: no metadata carried over
    media_type = "image/png"
    if out.tell() > 3_500_000:  # photos compress badly as PNG; keep under the API image limit
        out = io.BytesIO()
        img.save(out, format="JPEG", quality=88)
        media_type = "image/jpeg"
    return media_type, base64.standard_b64encode(out.getvalue()).decode()
