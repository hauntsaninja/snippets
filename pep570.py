import argparse
import os
import sys

import libcst as cst
from libcst.codemod import (
    CodemodContext,
    TransformSuccess,
    VisitorBasedCodemodCommand,
    gather_files,
    parallel_exec_transform_with_prettyprint,
    transform_module,
)


class PEP570Command(VisitorBasedCodemodCommand):
    def leave_Parameters(
        self, original_node: cst.Parameters, updated_node: cst.Parameters
    ) -> cst.Parameters:
        if updated_node.posonly_params:
            return updated_node

        pos_only_count = 0
        for i, param in enumerate(updated_node.params):
            if i == 0 and param.name.value in {"self", "cls", "mcls", "metacls"}:
                continue
            if not param.name.value.startswith("__"):
                break
            pos_only_count = i + 1

        if not pos_only_count:
            return updated_node

        params = updated_node.params[pos_only_count:]
        posonly_params = [
            p.with_changes(name=p.name.with_changes(value=p.name.value.removeprefix("__")))
            for p in updated_node.params[:pos_only_count]
        ]
        posonly_ind = cst.ParamSlash()

        return updated_node.with_changes(
            params=params, posonly_params=posonly_params, posonly_ind=posonly_ind
        )


def main() -> int:
    test()

    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="+")
    args = parser.parse_args()

    bases = list(map(os.path.abspath, args.path))
    root = os.path.commonpath(bases)
    root = os.path.dirname(root) if os.path.isfile(root) else root

    files = gather_files(bases, include_stubs=True)
    try:
        result = parallel_exec_transform_with_prettyprint(
            PEP570Command(CodemodContext()), files, repo_root=root
        )
    except KeyboardInterrupt:
        print("Interrupted!", file=sys.stderr)
        return 2

    print(
        f"Finished codemodding {result.successes + result.skips + result.failures} files!",
        file=sys.stderr,
    )
    print(f" - Transformed {result.successes} files successfully.", file=sys.stderr)
    print(f" - Skipped {result.skips} files.", file=sys.stderr)
    print(f" - Failed to codemod {result.failures} files.", file=sys.stderr)
    print(f" - {result.warnings} warnings were generated.", file=sys.stderr)
    return 1 if result.failures > 0 else 0


def test() -> None:
    cmd = PEP570Command(CodemodContext())

    result = transform_module(cmd, "def foo(a, b): pass")
    assert isinstance(result, TransformSuccess)
    assert result.code == "def foo(a, b): pass"

    result = transform_module(cmd, "def foo(__a, b): pass")
    assert isinstance(result, TransformSuccess)
    assert result.code == "def foo(a, /, b): pass"

    result = transform_module(cmd, "def foo(__a, __b): pass")
    assert isinstance(result, TransformSuccess)
    assert result.code == "def foo(a, b, /): pass"

    result = transform_module(cmd, "def foo(__a, __b, __c, d): pass")
    assert isinstance(result, TransformSuccess)
    assert result.code == "def foo(a, b, c, /, d): pass"

    result = transform_module(cmd, "def foo(a, /, b): pass")
    assert isinstance(result, TransformSuccess)
    assert result.code == "def foo(a, /, b): pass"

    result = transform_module(cmd, "class A:\n def foo(self, __a, b): pass")
    assert isinstance(result, TransformSuccess)
    assert result.code == "class A:\n def foo(self, a, /, b): pass"

    result = transform_module(cmd, "class A:\n def foo(self, b): pass")
    assert isinstance(result, TransformSuccess)
    assert result.code == "class A:\n def foo(self, b): pass"

    result = transform_module(cmd, "class A:\n def foo(cls, __a, b): pass")
    assert isinstance(result, TransformSuccess)
    assert result.code == "class A:\n def foo(cls, a, /, b): pass"


if __name__ == "__main__":
    sys.exit(main())
