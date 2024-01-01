from __future__ import annotations

import argparse
import asyncio
import collections
import email.parser
import enum
import functools
import importlib.metadata
import io
import sys
import zipfile
from pathlib import Path
from typing import Any

import aiohttp
import packaging.tags
import packaging.utils
import packaging.version
from packaging.version import Version


class PythonSupport(enum.IntEnum):
    unsupported = 0
    totally_unknown = 1
    has_viable_wheel = 2
    has_explicit_wheel = 3
    has_classifier = 4


@functools.cache
def interpreter_value(python_version: tuple[int, int]) -> str:
    nodot = "".join(map(str, python_version))
    assert sys.implementation.name == "cpython"
    return f"cp{nodot}"


@functools.cache
def valid_interpreter_abi_set(python_version: tuple[int, int]) -> set[tuple[str, str]]:
    assert sys.implementation.name == "cpython"
    tags = set[packaging.tags.Tag]()
    # Note these values can be a little system dependent, but at least we mostly strip
    # platform dependence
    tags.update(packaging.tags.cpython_tags(python_version=python_version, abis=None))
    tags.update(
        packaging.tags.compatible_tags(
            python_version=python_version, interpreter=interpreter_value(python_version)
        )
    )
    return {(t.interpreter, t.abi) for t in tags}


def tag_works_for_python(tag: packaging.tags.Tag, python_version: tuple[int, int]) -> bool:
    return (tag.interpreter, tag.abi) in valid_interpreter_abi_set(python_version)


async def support_from_wheels(
    session: aiohttp.ClientSession, wheels: list[dict[str, Any]], python_version: tuple[int, int]
) -> PythonSupport:
    if not wheels:
        return PythonSupport.totally_unknown

    support = PythonSupport.unsupported
    best_wheel = None

    for file in wheels:
        _, _, _, tags = packaging.utils.parse_wheel_filename(file["filename"])
        for tag in tags:
            # If we have a wheel specifically for this version, we're definitely supported
            if tag.interpreter == interpreter_value(python_version):
                support = PythonSupport.has_explicit_wheel
                if best_wheel is None or file.get("core-metadata"):
                    best_wheel = file
            # If we have a wheel that works for this version, we're maybe supported
            if tag_works_for_python(tag, python_version):
                if support < PythonSupport.has_viable_wheel:
                    support = PythonSupport.has_viable_wheel
                    if best_wheel is None or file.get("core-metadata"):
                        best_wheel = file

    assert support <= PythonSupport.has_explicit_wheel
    if support == PythonSupport.unsupported:
        # We have no wheels that work for this version (and there are other wheels)
        # (don't bother to check if there is a classifier if we'd have to build sdist for support)
        return support
    assert support >= PythonSupport.has_viable_wheel

    # We have wheels that are at least viable for this version — time to check the classifiers!
    assert best_wheel is not None

    if best_wheel.get("core-metadata"):
        url = best_wheel["url"] + ".metadata"
        async with session.get(url) as resp:
            resp.raise_for_status()
            content = io.BytesIO(await resp.read())
        parser = email.parser.BytesParser()
        metadata = parser.parse(content)
    else:
        url = best_wheel["url"]
        async with session.get(url) as resp:
            resp.raise_for_status()
            body = io.BytesIO(await resp.read())
            with zipfile.ZipFile(body) as zf:
                metadata_file = next(
                    n
                    for n in zf.namelist()
                    if Path(n).name == "METADATA" and Path(n).parent.suffix == ".dist-info"
                )
                with zf.open(metadata_file) as f:
                    parser = email.parser.BytesParser()
                    metadata = parser.parse(f)

    classifiers = set(metadata.get_all("Classifier", []))
    python_version_str = ".".join(str(v) for v in python_version)
    if f"Programming Language :: Python :: {python_version_str}" in classifiers:
        return PythonSupport.has_classifier
    return support


def safe_version(v: str) -> Version:
    try:
        return Version(v)
    except packaging.version.InvalidVersion:
        return Version("0")


async def project_support(
    session: aiohttp.ClientSession, name: str, python_version: tuple[int, int]
) -> tuple[Version, PythonSupport]:
    headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
    async with session.get(f"https://pypi.org/simple/{name}/", headers=headers) as resp:
        if resp.status == 404:
            return Version("0"), PythonSupport.totally_unknown
        resp.raise_for_status()
        data = await resp.json()

    version_wheels = collections.defaultdict[Version, list[dict[str, Any]]](list)

    for file in data["files"]:
        if not file["filename"].endswith(".whl"):
            continue
        _, version, _, _ = packaging.utils.parse_wheel_filename(file["filename"])
        if version.is_prerelease:
            continue
        version_wheels[version].append(file)

    all_versions = sorted((safe_version(v) for v in data["versions"]), reverse=True)
    all_versions = [v for v in all_versions if not v.is_prerelease]
    if not all_versions:
        return Version("0"), PythonSupport.totally_unknown
    latest_version = all_versions[0]

    support = await support_from_wheels(session, version_wheels[latest_version], python_version)
    if support <= PythonSupport.has_viable_wheel:
        return latest_version, support

    # Try to figure out which version added the classifier / explicit wheel
    # Just do a dumb linear search
    earliest_supported_version = latest_version
    for version in all_versions:
        if version == latest_version:
            continue
        version_support = await support_from_wheels(
            session, version_wheels[version], python_version
        )
        if version_support < support:
            return earliest_supported_version, support
        earliest_supported_version = version

    return earliest_supported_version, support


async def main() -> None:
    assert sys.version_info >= (3, 9)

    parser = argparse.ArgumentParser()
    parser.add_argument("--python", default="3.12")
    parser.add_argument("-p", "--project", action="append")
    args = parser.parse_args()

    python_version: tuple[int, int] = tuple(map(int, args.python.split(".")))  # type: ignore
    assert len(python_version) == 2
    projects = args.project
    if not projects:
        projects = {dist.metadata["Name"] for dist in importlib.metadata.distributions()}

    async with aiohttp.ClientSession() as session:
        supports: list[tuple[Version, PythonSupport]] = await asyncio.gather(
            *(project_support(session, proj, python_version) for proj in projects)
        )
        proj_support = dict(zip(projects, supports, strict=True))
        for proj, (version, support) in sorted(
            proj_support.items(), key=lambda x: (-x[1][1].value, x[0])
        ):
            constraint = f"{proj}>={version}"
            print(f"{constraint:<25}  # {support.name}")


if __name__ == "__main__":
    asyncio.run(main())
