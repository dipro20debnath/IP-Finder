"""Download MaxMind GeoLite2 databases the way MaxMind's own geoipupdate tool does
(checked against github.com/maxmind/geoipupdate, client/metadata.go and download.go):

  GET https://updates.maxmind.com/geoip/updates/metadata?edition_id=GeoLite2-City
      -> {"databases": [{"edition_id": "GeoLite2-City", "date": "2026-10-07", "md5": "..."}]}
  GET https://updates.maxmind.com/geoip/databases/GeoLite2-City/download?date=20261007&suffix=tar.gz
      -> redirect to a presigned URL -> a .tar.gz holding GeoLite2-City.mmdb
Both requests use HTTP basic auth: user = account ID, password = license key (from
your free MaxMind account). Nothing is downloaded when the local file's MD5
already matches the latest build.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import maxminddb

from ipfinder.core.config import Config
from ipfinder.core.errors import ProviderError
from ipfinder.core.http import fetch_bytes, request_json

ENDPOINT = "https://updates.maxmind.com"
EDITIONS = (("GeoLite2-City", "maxmind_city_db"), ("GeoLite2-ASN", "maxmind_asn_db"))
MAX_ARCHIVE = 300_000_000
MAX_MMDB = 600_000_000


def _md5(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def file_md5(path: Path) -> str | None:
    digest = hashlib.md5(usedforsecurity=False)
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def extract_mmdb(archive: bytes) -> bytes:
    """The .mmdb file inside a GeoLite2 .tar.gz. Nothing is written by member name,
    so a hostile archive cannot place files elsewhere."""
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                if member.isfile() and member.name.endswith(".mmdb"):
                    if member.size > MAX_MMDB:
                        raise ProviderError("the database in the archive is unexpectedly large")
                    handle = tar.extractfile(member)
                    if handle is not None:
                        return handle.read()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ProviderError(f"cannot read the downloaded archive ({exc})") from None
    raise ProviderError("the downloaded archive holds no .mmdb file")


def install_mmdb(data: bytes, path: Path, edition: str) -> str:
    """Check that ``data`` is a readable ``edition`` database, then replace ``path``.
    Returns the database build date."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(data)
        try:
            with maxminddb.open_database(str(tmp)) as reader:
                meta = reader.metadata()
        except (maxminddb.InvalidDatabaseError, ValueError, OSError) as exc:
            raise ProviderError(f"the downloaded database is not readable ({exc})") from None
        if not str(meta.database_type).startswith(edition):
            raise ProviderError(f"expected {edition}, got {meta.database_type}")
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()
    return datetime.fromtimestamp(meta.build_epoch, timezone.utc).strftime("%Y-%m-%d")


async def update_maxmind(session, config: Config, force: bool = False) -> list[dict[str, Any]]:
    account = config.key_for("MAXMIND_ACCOUNT_ID")
    key = config.key_for("MAXMIND_LICENSE_KEY")
    if not (account and key):
        return [
            {
                "name": "maxmind",
                "status": "skipped",
                "error": "set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in .env "
                "(free account: https://www.maxmind.com/en/geolite2/signup)",
            }
        ]
    auth = (account, key)
    results = []
    for edition, attr in EDITIONS:
        path = Path(getattr(config, attr))
        name = f"maxmind {edition}"
        try:
            _, meta = await request_json(
                session,
                "GET",
                f"{ENDPOINT}/geoip/updates/metadata",
                params={"edition_id": edition},
                auth=auth,
            )
            databases = meta.get("databases") if isinstance(meta, dict) else None
            latest = next(
                (
                    d
                    for d in databases or []
                    if isinstance(d, dict) and d.get("edition_id") == edition
                ),
                None,
            )
            if latest is None or not latest.get("date"):
                raise ProviderError("MaxMind did not report the latest build")
            md5, date = latest.get("md5"), str(latest["date"])
            if not force and md5 and path.is_file() and file_md5(path) == md5:
                results.append({"name": name, "status": "fresh", "published": date})
                continue
            query = urlencode({"date": date.replace("-", ""), "suffix": "tar.gz"})
            archive, _ = await fetch_bytes(
                session,
                f"{ENDPOINT}/geoip/databases/{edition}/download?{query}",
                max_bytes=MAX_ARCHIVE,
                auth=auth,
            )
            data = extract_mmdb(archive)
            if md5 and _md5(data) != md5:
                raise ProviderError("checksum mismatch; the download was corrupted")
            build = install_mmdb(data, path, edition)
            results.append(
                {"name": name, "status": "updated", "published": build, "path": str(path)}
            )
        except (ProviderError, OSError) as exc:
            results.append({"name": name, "status": "failed", "error": str(exc)})
    return results
