from __future__ import annotations

import argparse
import asyncio
import functools
import importlib.metadata
import re
import sysconfig
from pathlib import Path

import aiohttp
import packaging.version
from packaging.requirements import Requirement
from packaging.version import Version


def safe_version(v: str) -> Version:
    try:
        return Version(v)
    except packaging.version.InvalidVersion:
        return Version("0")


async def dist_support(session: aiohttp.ClientSession, req: Requirement) -> int:
    headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
    async with session.get(f"https://pypi.org/simple/{req.name}/", headers=headers) as resp:
        if resp.status == 404:
            return 0
        resp.raise_for_status()
        data = await resp.json()

    all_versions = sorted((safe_version(v) for v in data["versions"]), reverse=True)
    return sum(1 for version in all_versions if req.specifier.contains(version))


def parse_requirements_txt(req_file: str) -> list[str]:
    def strip_comments(s: str) -> str:
        try:
            return s[: s.index("#")].strip()
        except ValueError:
            return s.strip()

    entries = []
    with open(req_file) as f:
        for line in f:
            entry = strip_comments(line)
            if entry:
                entries.append(entry)
    return entries


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def combine_reqs(reqs: list[Requirement]) -> Requirement:
    assert reqs
    combined = Requirement(str(reqs[0]))
    for req in reqs[1:]:
        assert canonical_name(combined.name) == canonical_name(req.name)
        # It would be nice if there was an officially sanctioned way of combining these
        if combined.url and req.url and combined.url != req.url:
            raise RuntimeError(f"Conflicting URLs for {combined.name}: {combined.url} vs {req.url}")
        combined.url = combined.url or req.url
        combined.extras.update(req.extras)
        combined.specifier &= req.specifier
        if combined.marker and req.marker:
            # Note that if a marker doesn't pan out, it can still contribute its version specifier
            # to the combined requirement
            combined.marker._markers = [combined.marker._markers, "or", req.marker._markers]
        else:
            # If one of markers is None, that is an unconditional install
            combined.marker = None
    return combined


def deduplicate_reqs(reqs: list[Requirement]) -> list[Requirement]:
    simplified: dict[str, list[Requirement]] = {}
    for req in reqs:
        simplified.setdefault(canonical_name(req.name), []).append(req)
    return [combine_reqs(reqs) for reqs in simplified.values()]


@functools.lru_cache()
def sysconfig_purelib() -> Path:
    return Path(sysconfig.get_paths()["purelib"])


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--constraint")
    args = parser.parse_args()

    requirements = []
    if args.constraint:
        requirements = [Requirement(req) for req in parse_requirements_txt(args.constraint)]
    for dist in importlib.metadata.distributions():
        if (
            isinstance(dist, importlib.metadata.PathDistribution)
            and (dist_path := getattr(dist, "_path", None))
            and isinstance(dist_path, Path)
            and not dist_path.is_relative_to(sysconfig_purelib())
        ):
            continue
        requirements.append(Requirement(dist.name))
    requirements = deduplicate_reqs(requirements)

    async with aiohttp.ClientSession() as session:
        counts = await asyncio.gather(*(dist_support(session, req) for req in requirements))
        req_counts = sorted(
            zip(requirements, counts, strict=True), key=lambda x: x[1], reverse=True
        )
        for req, count in req_counts:
            print(f"{req} ({count})")


if __name__ == "__main__":
    asyncio.run(main())
