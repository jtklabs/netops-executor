"""Verified local image cache; HTTPS downloads are atomic and cancellable."""

import os
import time
from urllib.parse import urlsplit

import httpx

from .config import under
from .ssh import DeviceError, digest


def cached_image(settings, image, job_id, checkpoint):
    local = under(settings.image_root, image.name)
    if local.is_file() and digest(local) == image.sha256:
        return local
    if not image.source_url:
        return local
    parsed = urlsplit(image.source_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DeviceError("image URL requires HTTPS without embedded credentials")
    settings.image_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    partial = under(settings.image_root, "." + job_id + ".download")
    deadline, total = time.monotonic() + 7200, 0
    try:
        with httpx.stream(
            "GET", image.source_url, timeout=60, follow_redirects=False, trust_env=False
        ) as response:
            response.raise_for_status()
            with partial.open("wb") as stream:
                for chunk in response.iter_bytes(1024 * 1024):
                    checkpoint()
                    total += len(chunk)
                    if total > 30 * 1024**3 or time.monotonic() > deadline:
                        raise DeviceError("image download exceeded 30 GiB or two hours")
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
        if digest(partial) != image.sha256:
            raise DeviceError("downloaded image SHA-256 mismatch")
        os.replace(partial, local)
        return local
    except httpx.HTTPError:
        raise DeviceError("image download failed") from None
    finally:
        partial.unlink(missing_ok=True)
