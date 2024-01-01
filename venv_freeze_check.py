import functools
import importlib.metadata
import re
import sysconfig
from pathlib import Path

import packaging.markers
import packaging.requirements
import packaging.version


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@functools.lru_cache()
def sysconfig_purelib() -> Path:
    return Path(sysconfig.get_paths()["purelib"])


def safe_req_parse(r: str) -> packaging.requirements.Requirement | None:
    # https://github.com/pypa/packaging/issues/494
    try:
        return packaging.requirements.Requirement(r)
    except packaging.requirements.InvalidRequirement:
        return None


def req_is_needed_in_current_environment(req: packaging.requirements.Requirement) -> bool:
    if req.marker is None:
        return True
    try:
        return req.marker.evaluate()
    except packaging.markers.UndefinedEnvironmentName:
        # likely because the req has an extra
        return False


def freeze_and_check() -> None:
    # This is very similar to `pip freeze` + `pip check`, except much faster
    versions = {}
    reqs = {}
    paths = {}
    for dist in importlib.metadata.distributions():
        metadata = dist.metadata
        name = canonical_name(metadata["Name"])
        versions[name] = packaging.version.parse(metadata["Version"])
        # TODO: check if d.requires is None means anything
        reqs[name] = [req for r in (dist.requires or []) if (req := safe_req_parse(r)) is not None]
        paths[name] = dist._path if isinstance(dist, importlib.metadata.PathDistribution) else None

    # Like `pip check`, we don't handle extras very well https://github.com/pypa/pip/issues/4086
    # This is because there's no way to tell if an extra was requested. If we wanted, we could
    # do slightly better than pip by finding all requirements that require an extra and using that
    # as a heuristic to tell if an extra was requested.

    # pip freeze-like
    sorted_versions = sorted(versions.items(), key=lambda x: x[0])

    _in_purelib = []
    _outside_purelib = []
    for package, version in sorted_versions:
        if isinstance(paths[package], Path) and paths[package].is_relative_to(sysconfig_purelib()):  # type: ignore[union-attr]
            _in_purelib.append(f"{package}=={version}")
        else:
            _outside_purelib.append(f"{package}=={version}  # {paths[package]}")
    for line in sorted(_in_purelib):
        print(line)
    for line in sorted(_outside_purelib):
        print(line)
    print("\n" + "=" * 40 + "\n")

    # pip check-like
    for package, version in sorted_versions:
        for req in reqs[package]:
            req_name = canonical_name(req.name)

            if not req_is_needed_in_current_environment(req):
                continue

            if req_name in versions:
                if not req.specifier.contains(versions[req_name], prereleases=True):
                    print(
                        f"{package} {version} requires {req}, "
                        f"but {versions[req_name]} is installed"
                    )
                continue

            print(f"{package} {version} is missing requirement {req}")


if __name__ == "__main__":
    freeze_and_check()
