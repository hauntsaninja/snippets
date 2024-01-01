#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import enum
import functools
import hashlib
import importlib
import math
import os
import pickle
import shlex
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    import gitignorefile  # type: ignore[import-untyped]
    import watchfiles
    import zstandard
else:
    deps = ["gitignorefile", "watchfiles", "zstandard"]
    for package in deps:
        try:
            globals()[package] = importlib.import_module(package)
        except ModuleNotFoundError:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *deps]
            )
            globals()[package] = importlib.import_module(package)

PORT = 3000

ZSTD_LEVEL = 4

LOG_LEVEL = 0


def set_log_level(level: int | None) -> None:
    if level is None:
        return
    global LOG_LEVEL
    LOG_LEVEL = level


def log(msg: str, level: int) -> None:
    if level > LOG_LEVEL:
        return
    if level >= 1:
        print(f"\033[90m{msg}\033[0m")
        return
    print(msg)


class Timer:
    def __init__(self, name: str = "", log_level: int | None = None) -> None:
        self._name = name
        self._start: int | None = None
        self._end: int | None = None
        self._log_level = log_level

    def start(self) -> "Timer":
        self._start = time.perf_counter_ns()
        return self

    def end(self) -> "Timer":
        self._end = time.perf_counter_ns()
        return self

    def time(self) -> float:
        assert self._start is not None
        assert self._end is not None
        return (self._end - self._start) / 1e9

    def __str__(self) -> str:
        return f"{self.time():.3f}s"

    def log(self, level: int) -> None:
        log(f"{self._name}: {self}", level=level)

    def __enter__(self) -> "Timer":
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.end()
        if self._log_level is not None:
            self.log(level=self._log_level)


# ==============================
# Networking helpers
# ==============================


def write_length_prefixed(buf: bytearray, data: bytes) -> None:
    """Write the length of the data as a 64-bit int, followed by the data itself."""
    buf.extend(len(data).to_bytes(8, byteorder="big"))
    buf.extend(data)


async def read_length_prefixed_async(reader: asyncio.StreamReader) -> bytes:
    """Read a length-prefixed message from the socket."""
    try:
        header = await reader.readexactly(8)
        assert len(header) == 8
        payload_length = int.from_bytes(header, byteorder="big")
        return await reader.readexactly(payload_length)
    except Exception as e:
        e.add_note(
            f"Exception occurred communicating with {reader._transport.get_extra_info('peername')}\n"  # type: ignore[attr-defined]
            "Consider checking server side logs."
        )
        raise


def get_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**22)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**22)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if sys.platform == "linux":
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
    return sock


STREAM_READER_LIMIT = 2**24


async def open_connection(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=STREAM_READER_LIMIT, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    sock = get_socket()
    sock.settimeout(10)
    sock.connect((host, port))
    sock.settimeout(None)
    transport, _ = await loop.create_connection(lambda: protocol, sock=sock)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer


# ==============================
# File system helpers
# ==============================


def collect_file_size_mtimes(
    path: str, ignore_cache: gitignorefile.Cache
) -> dict[str, tuple[int, float]]:
    prefix_len = len(path) + 1
    stats: dict[str, tuple[int, float]] = {}
    try:
        stack: list[os.DirEntry[str]] = list(os.scandir(path))
    except FileNotFoundError:
        os.makedirs(path, exist_ok=True)
        return {}
    while stack:
        item = stack.pop()
        item_is_dir = item.is_dir(follow_symlinks=False)
        if ignore_cache(item.path, is_dir=item_is_dir):
            continue
        if item_is_dir:
            stack.extend(os.scandir(item.path))
            continue
        if item.is_symlink():
            # TODO: we don't support symlinks
            continue
        item_stat = item.stat(follow_symlinks=False)
        stats[item.path[prefix_len:]] = (item_stat.st_size, item_stat.st_mtime)
    return stats


# ==============================
# Server definition
# ==============================


class ServerOperation(enum.IntEnum):
    HEALTHCHECK = 3
    FILE_BATCH = 5
    LIST_SIZES_SOME_MTIMES = 7
    SELF_KILL = 11
    BENCHMARK_UPLOAD = 13


class FileOperation(enum.IntEnum):
    WRITE = 43
    DELETE = 44


TreeTopo = dict[tuple[str, int], "TreeTopo"]


async def forward_to_topo(
    topo: TreeTopo, op: ServerOperation, payloads: list[bytes]
) -> list[bytes]:
    async def forward_one(host: str, port: int) -> bytes:
        reader, writer = await open_connection(host, port)
        buf = bytearray()
        buf.extend(op.to_bytes(8, byteorder="big"))
        for payload in payloads:
            write_length_prefixed(buf, payload)
        write_length_prefixed(buf, pickle.dumps(topo[(host, port)]))

        writer.write(buf)
        await writer.drain()

        response = await read_length_prefixed_async(reader)

        writer.close()
        await writer.wait_closed()

        return response

    with Timer(f"t_forward to {len(topo)} nodes") as t:
        ret = await asyncio.gather(*[forward_one(host, port) for (host, port) in topo])
    t.log(level=1)

    return ret


def _perform_op(op: tuple[Any, ...], dst: str) -> None:
    op_type = op[0]
    if op_type == FileOperation.WRITE:
        path = os.path.join(dst, op[1])
        contents = op[2]
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except FileExistsError:
            os.remove(path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
        log(f"Writing {len(contents)} bytes to {path}", level=2)
        try:
            with open(path, "wb") as f:
                f.write(contents)
        except IsADirectoryError:
            shutil.rmtree(path, ignore_errors=True)
            with open(path, "wb") as f:
                f.write(contents)
    elif op_type == FileOperation.DELETE:
        path = os.path.join(dst, op[1])
        log(f"Deleting {path}", level=2)
        try:
            os.remove(path)
        except (FileNotFoundError, IsADirectoryError):
            # If the file is not found, we've already done our job
            # If the file is now a directory, that's fine too
            pass
    else:
        raise ValueError(f"Unknown file operation: {op}")


def _perform_ops(ops: list[tuple[Any, ...]], dst: str) -> None:
    for op in ops:
        _perform_op(op, dst)


class Handler:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.version = self_version()

    async def healthcheck(self) -> None:
        topo = pickle.loads(await read_length_prefixed_async(self.reader))
        for _ in range(50):
            try:
                forward_responses = await forward_to_topo(topo, ServerOperation.HEALTHCHECK, [])
                break
            except ConnectionRefusedError as e:
                log(f"Connection refused when healthchecking, retrying: {e}", level=1)
                await asyncio.sleep(0.1)
        else:
            forward_responses = [b"simplesyncunhealthy"]

        log(f"forward_responses: {set(forward_responses)}", level=1)

        healthy_response = b"simplesync" + self.version
        buf = bytearray()
        if all(response == healthy_response for response in forward_responses):
            write_length_prefixed(buf, healthy_response)
        elif all(response.startswith(b"simplesync") for response in forward_responses):
            bad_response = next(r for r in forward_responses if r != healthy_response)
            write_length_prefixed(buf, bad_response)
        else:
            write_length_prefixed(buf, forward_responses[0])
        self.writer.write(buf)
        await self.writer.drain()

    async def file_batch(self) -> None:
        with Timer("t_payload", log_level=1):
            dst_ops_payload = await read_length_prefixed_async(self.reader)
            log(f"payload size: {len(dst_ops_payload):_} bytes", level=1)

        with Timer("t_load", log_level=1):
            dst, ops = pickle.loads(zstandard.decompress(dst_ops_payload))
            log(f"dst: {dst}", level=1)
            log(f"num ops: {len(ops)}", level=1)

        with Timer("t_topo", log_level=1):
            topo = pickle.loads(await read_length_prefixed_async(self.reader))
            log(f"topo: {topo}", level=2)

        forward_task = asyncio.create_task(
            forward_to_topo(topo, ServerOperation.FILE_BATCH, [dst_ops_payload])
        )

        with Timer("t_perform_ops", log_level=1):
            await asyncio.get_running_loop().run_in_executor(None, _perform_ops, ops, dst)

        with Timer("t_forward_latency", log_level=1):
            forward_responses = await forward_task

            if not all(response == b"SYNCED" for response in forward_responses):
                buf = bytearray()
                write_length_prefixed(buf, b"FAILED")
                self.writer.write(buf)
                await self.writer.drain()
                return

        with Timer("t_resp", log_level=1):
            buf = bytearray()
            write_length_prefixed(buf, b"SYNCED")
            self.writer.write(buf)
            await self.writer.drain()

    async def list_sizes_some_mtimes(self) -> None:
        with Timer("t_payload_load", log_level=1):
            dst = pickle.loads(await read_length_prefixed_async(self.reader))
            need_mtimes = pickle.loads(await read_length_prefixed_async(self.reader))
            topo = pickle.loads(await read_length_prefixed_async(self.reader))
            log(f"topo: {topo}", level=2)

        with Timer("t_setup", log_level=1):
            ignore_cache = gitignorefile.Cache()
            file_size_mtimes_future = asyncio.get_running_loop().run_in_executor(
                None, collect_file_size_mtimes, dst, ignore_cache
            )
            forward_task = asyncio.create_task(
                forward_to_topo(
                    topo,
                    ServerOperation.LIST_SIZES_SOME_MTIMES,
                    # need_mtimes=False
                    [pickle.dumps(dst), pickle.dumps(False)],
                )
            )

        with Timer("t_file_sizes_latency", log_level=1):
            file_size_mtimes = await file_size_mtimes_future

        with Timer("t_file_sizes_overhead", log_level=1):
            file_sizes = {k: v[0] for k, v in file_size_mtimes.items()}

        with Timer("t_forward_latency", log_level=1):
            forward_responses = await forward_task

        with Timer("t_forward_combine", log_level=1):
            for forward_response in forward_responses:
                remote_sizes = pickle.loads(zstandard.decompress(forward_response))
                # symmetric difference of items (missing keys or mismatched values)
                for relpath, _ in file_sizes.items() ^ remote_sizes.items():
                    file_sizes[relpath] = -1  # something that will never match client

        with Timer("t_maybe_mtimes", log_level=1):
            if need_mtimes:
                # while we reduce sizes, mtimes are only from one node
                ret = {}
                for relpath, size in file_sizes.items():
                    if size == -1:
                        continue
                    ret[relpath] = (size, file_size_mtimes[relpath][1])
            else:
                ret = file_sizes

        with Timer("t_dump", log_level=1):
            response_payload = zstandard.compress(pickle.dumps(ret), level=ZSTD_LEVEL)
            log(f"response payload size: {len(response_payload):_} bytes", level=1)

        with Timer("t_resp", log_level=1):
            buf = bytearray()
            write_length_prefixed(buf, response_payload)
            self.writer.write(buf)
            await self.writer.drain()

    async def self_kill(self) -> None:
        log("Received self-kill signal...", level=0)

        topo = pickle.loads(await read_length_prefixed_async(self.reader))
        try:
            forward_responses = await forward_to_topo(topo, ServerOperation.SELF_KILL, [])
        except Exception as e:
            log(f"Exception when forwarding self-kill: {e}", level=0)
            forward_responses = [b"GOODBYE"]

        if not all(response == b"GOODBYE" for response in forward_responses):
            log("Failed to kill all nodes :-/", level=0)

        log("Hard exiting...", level=0)
        buf = bytearray()
        write_length_prefixed(buf, b"GOODBYE")
        self.writer.write(buf)
        await self.writer.drain()
        self.writer.close()
        await self.writer.wait_closed()

        os._exit(0)

    async def benchmark_upload(self) -> None:
        with Timer("t_payload", log_level=0):
            payload = await read_length_prefixed_async(self.reader)
            log(f"payload size: {len(payload):_} bytes", level=0)

        with Timer("t_resp", log_level=0):
            buf = bytearray()
            write_length_prefixed(buf, len(payload).to_bytes(8, byteorder="big"))
            self.writer.write(buf)
            await self.writer.drain()

    async def handle(self) -> None:
        log(
            f"Connection opened from {self.writer._transport.get_extra_info('peername')}",  # type: ignore[attr-defined]
            level=0,
        )

        try:
            while True:
                log("\nWaiting for operation...", level=0)
                try:
                    header = await self.reader.readexactly(8)
                except asyncio.IncompleteReadError as e:
                    raise ConnectionError("IncompleteReadError") from e

                assert len(header) == 8
                operation = int.from_bytes(header, byteorder="big")

                try:
                    server_operation = ServerOperation(operation)
                except ValueError:
                    log(f"Received unknown server operation: {operation}, hard exiting...", level=0)
                    os._exit(0)

                log(
                    f"Received operation {server_operation.name} from "
                    f"{self.writer._transport.get_extra_info('peername')}",  # type: ignore[attr-defined]
                    level=0,
                )

                # TODO: we use pickle a fair amount, but this won't work well for non-simple
                # data types since we're in a different module on the server

                if operation == ServerOperation.HEALTHCHECK:
                    await self.healthcheck()
                    continue

                if operation == ServerOperation.FILE_BATCH:
                    await self.file_batch()
                    continue

                if operation == ServerOperation.LIST_SIZES_SOME_MTIMES:
                    await self.list_sizes_some_mtimes()
                    continue

                if operation == ServerOperation.SELF_KILL:
                    await self.self_kill()
                    continue

                if operation == ServerOperation.BENCHMARK_UPLOAD:
                    await self.benchmark_upload()
                    continue

                raise AssertionError(f"Unhandled server operation: {operation}")

        except ConnectionError as e:
            log(f"Connection closed by client: {e}", level=0)
        except Exception as e:
            log(f"Unexpected error: {e}", level=0)
            import traceback

            traceback.print_exc()


async def server() -> None:
    sock = get_socket()

    sock.bind(("0.0.0.0", PORT))
    sock.settimeout(None)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await Handler(reader, writer).handle()

    server = await asyncio.start_server(handler, sock=sock, limit=STREAM_READER_LIMIT)
    async with server:
        await server.serve_forever()


@functools.lru_cache()
def self_version() -> bytes:
    with open(__file__, "rb") as f:
        return hashlib.md5(f.read()).hexdigest().encode()


# ==============================
# Client
# ==============================


def op_from_path(*, path: str, relpath: str) -> tuple[Any, ...] | None:
    try:
        if os.path.islink(path):
            # TODO: we don't support symlinks
            return None
        try:
            with open(path, "rb") as f:
                contents = f.read()
        except IsADirectoryError:
            # I think this happens if a file is deleted and a directory is created?
            return None
        # TODO: mode
        return (FileOperation.WRITE.value, relpath, contents)
    except FileNotFoundError:
        return (FileOperation.DELETE.value, relpath)


@dataclass
class Connection:
    host: str
    port: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    forwards: list[tuple[str, int]]

    def num_nodes(self) -> int:
        return len(self.forwards) + 1

    @functools.cached_property
    def flat_topo(self) -> TreeTopo:
        return {f: {} for f in self.forwards}

    @functools.cached_property
    def l2_topo(self) -> TreeTopo:
        if len(self.forwards) < 12:
            return self.flat_topo

        # solve for even branching
        k = int((math.sqrt(4 * len(self.forwards) + 1) - 1) // 2)
        assert k >= 3

        ret: TreeTopo = {}
        for i in range(k):
            ret[self.forwards[i]] = {f: {} for f in self.forwards[k + i :: k]}
        assert sum(len(v) for v in ret.values()) + len(ret) == len(self.forwards)
        return ret


def ops_from_changed_paths(src, relpaths: list[str]) -> tuple[list[tuple[Any, ...]], int]:
    def helper(relpath: str) -> tuple[Any, ...] | None:
        return op_from_path(path=os.path.join(src, relpath), relpath=relpath)

    ops = []
    n_bytes = 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        for op in pool.map(helper, relpaths):
            if op is None:
                continue
            if op[0] == FileOperation.WRITE.value:
                assert isinstance(op[2], bytes)
                n_bytes += len(op[2])
            ops.append(op)

    return ops, n_bytes


async def sync_ops(dst: str, ops: list[tuple[Any, ...]], connections: list[Connection]) -> None:
    if not ops:
        return

    if len(ops) <= 10:
        for op in ops:
            log(f"{FileOperation(op[0]).name}, {op[1]}", level=1)

    with Timer("t_dump", log_level=1):
        payload = zstandard.compress(pickle.dumps((dst, ops)), level=ZSTD_LEVEL)
        log(f"ops payload size: {len(payload):_} bytes", level=1)

    with Timer("t_write", log_level=1):
        buf = bytearray()
        buf.extend(ServerOperation.FILE_BATCH.to_bytes(8, byteorder="big"))
        write_length_prefixed(buf, payload)
        for c in connections:
            c.writer.write(buf)
            topobuf = bytearray()
            # flat topo seems fine for most payload sizes, keep it simple and low latency
            write_length_prefixed(topobuf, pickle.dumps(c.flat_topo))
            c.writer.write(topobuf)

    with Timer("t_drain", log_level=1):
        await asyncio.gather(*[c.writer.drain() for c in connections])

    with Timer("t_resp", log_level=1):
        responses = await asyncio.gather(
            *[read_length_prefixed_async(c.reader) for c in connections]
        )
        if not all(response == b"SYNCED" for response in responses):
            raise RuntimeError("Failed to sync, check server side logs")


async def sync_initial_one(
    src: str,
    dst: str,
    local_size_mtimes_future: asyncio.Future[dict[str, tuple[int, float]]],
    connection: Connection,
    skip_mtime: bool,
    verbose: bool,
) -> tuple[int, int]:
    c = connection

    with Timer("t_read_list", log_level=1):
        payload = await read_length_prefixed_async(c.reader)
        log(f"list payload size: {len(payload):_} bytes", level=1)

    with Timer("t_load", log_level=1):
        remote_size_mtimes = pickle.loads(zstandard.decompress(payload))
        del payload

    with Timer("t_local_sizes_latency", log_level=1):
        local_size_mtimes = await local_size_mtimes_future
        if verbose:
            print("Finished local listing, waiting for remote...")

    with Timer("t_local_diff", log_level=1):
        delete_ops = []
        relpaths_changed = []
        relpaths_maybe_changed = []
        for relpath, (size, mtime) in local_size_mtimes.items():
            if relpath not in remote_size_mtimes:
                relpaths_changed.append(relpath)
                continue
            if size != remote_size_mtimes[relpath][0]:
                relpaths_changed.append(relpath)
                continue
            if mtime > remote_size_mtimes[relpath][1]:
                relpaths_maybe_changed.append(relpath)
                continue
        for relpath in remote_size_mtimes.keys() - local_size_mtimes.keys():
            delete_ops.append((FileOperation.DELETE.value, relpath))

    with Timer("t_local_ops", log_level=1):
        write_ops, n_bytes = ops_from_changed_paths(src=src, relpaths=relpaths_changed)
        ops = delete_ops + write_ops
        log(f"total file size: {n_bytes:_} bytes", level=1)

    if ops and verbose:
        print(f"Finished remote listing, {len(ops)} files and {n_bytes:_} bytes to sync...")

    total_num_ops = len(ops)
    total_n_bytes = n_bytes
    await sync_ops(dst=dst, ops=ops, connections=[c])

    if skip_mtime:
        return total_num_ops, total_n_bytes

    with Timer("t_local_ops_mtime", log_level=1):
        ops, n_bytes = ops_from_changed_paths(src=src, relpaths=relpaths_maybe_changed)
        log(f"total file size: {n_bytes:_} bytes", level=1)

    if ops and verbose:
        print(
            "Finished size-based sync, now doing mtime-based sync "
            "(use --skip-mtime to dangerously not do this), "
            f"{len(ops)} files and {n_bytes:_} bytes to sync..."
        )

    total_num_ops += len(ops)
    total_n_bytes += n_bytes
    await sync_ops(dst=dst, ops=ops, connections=[c])

    return total_num_ops, total_n_bytes


async def sync_initial(
    src: str,
    dst: str,
    local_size_mtimes_future: asyncio.Future[dict[str, tuple[int, float]]],
    connections: list[Connection],
    skip_mtime: bool,
) -> None:
    # With our current choice of topology, connections will be a list of size 1
    assert connections

    print("Beginning initial sync...")
    t_overall = Timer().start()

    with Timer("t_req_list", log_level=1):
        buf = bytearray()
        buf.extend(ServerOperation.LIST_SIZES_SOME_MTIMES.to_bytes(8, byteorder="big"))
        write_length_prefixed(buf, pickle.dumps(dst))
        write_length_prefixed(buf, pickle.dumps(True))
        for c in connections:
            c.writer.write(buf)
            topobuf = bytearray()
            # l2_topo helps here since there's a reduction involved
            write_length_prefixed(topobuf, pickle.dumps(c.l2_topo))
            c.writer.write(topobuf)

        await asyncio.gather(*[c.writer.drain() for c in connections])

    with Timer("t_sync", log_level=1):
        ops_and_bytes = await asyncio.gather(
            *[
                sync_initial_one(
                    src=src,
                    dst=dst,
                    local_size_mtimes_future=local_size_mtimes_future,
                    connection=c,
                    skip_mtime=skip_mtime,
                    verbose=(i == 0),
                )
                for i, c in enumerate(connections)
            ]
        )

    max_files, max_bytes = map(max, zip(*ops_and_bytes, strict=True))

    t_overall.end()
    print(
        f"Initial sync of {max_files} files and {max_bytes:_} bytes "
        f"to {sum(c.num_nodes() for c in connections)} nodes "
        f"completed in {t_overall} at {time.strftime('%H:%M:%S')}\n"
    )


async def sync_watcher_changes(
    src: str,
    dst: str,
    connections: list[Connection],
    ignore_cache: gitignorefile.Cache,
    changes: set[tuple[watchfiles.Change, str]],
) -> None:
    print(f"Detected {len(changes)} changes...")
    t_overall = Timer().start()

    change_by_path: dict[str, watchfiles.Change] = {}
    # changes is unordered and may contain duplicates. We deduplicate, preserving added
    # and modified changes over deleted changes (since we'll find out whether the file exists
    # or not when reading it)
    for change, path in changes:
        if ignore_cache(path):
            # ignore changes to gitignored files
            continue
        if path in change_by_path:
            if change in (watchfiles.Change.added, watchfiles.Change.modified):
                change_by_path[path] = change
        else:
            change_by_path[path] = change
    del changes

    if not change_by_path:
        print("No changes to sync\n")
        return

    with Timer("t_local_diff", log_level=1):
        delete_ops = []
        relpaths_changed = []
        for path, change in change_by_path.items():
            relpath = os.path.relpath(path, start=src)
            if change in (watchfiles.Change.added, watchfiles.Change.modified):
                relpaths_changed.append(relpath)
            elif change == watchfiles.Change.deleted:
                delete_ops.append((FileOperation.DELETE.value, relpath))

    with Timer("t_local_ops", log_level=1):
        write_ops, n_bytes = ops_from_changed_paths(src=src, relpaths=relpaths_changed)
        ops = delete_ops + write_ops
        log(f"total file size: {n_bytes:_} bytes", level=1)

    await sync_ops(dst=dst, ops=ops, connections=connections)

    t_overall.end()
    print(
        f"Sync of {len(ops)} files and {n_bytes:_} bytes to "
        f"{sum(c.num_nodes() for c in connections)} nodes "
        f"completed in {t_overall} at {time.strftime('%H:%M:%S')}\n"
    )


async def bootstrap(
    remotes: list[tuple[str, int]], run_callback: Callable[[str, str, str], Awaitable[None]]
) -> None:
    core_cmd = "cat > /tmp/simple_sync.py; python /tmp/simple_sync.py > /tmp/simple_sync.log 2>&1 &"
    bash_cmd = f"nohup bash --login -c {shlex.quote(core_cmd)}"
    await asyncio.gather(*(run_callback(host, bash_cmd, __file__) for host, _ in remotes))


async def establish_bootstrapped_connection(
    remotes: list[tuple[str, int]],
    run_callback: Callable[[str, str, str], Awaitable[None]],
    after_bootstrap: bool = False,
) -> Connection:
    for _ in range(5):  # arbitrary
        remote = remotes[0]
        forwards = remotes[1:]
        topo = {f: {} for f in forwards}

        host, port = remote

        if after_bootstrap:
            for _ in range(100):
                try:
                    reader, writer = await open_connection(host, port)
                    break
                except ConnectionRefusedError:
                    await asyncio.sleep(0.1)
            else:
                raise RuntimeError(f"Failed to establish connection with {host}:{port}")
        else:
            try:
                reader, writer = await open_connection(host, port)
            except ConnectionRefusedError:
                await bootstrap(remotes, run_callback)
                after_bootstrap = True
                continue

        buf = bytearray()
        buf.extend(ServerOperation.HEALTHCHECK.to_bytes(8, byteorder="big"))
        write_length_prefixed(buf, pickle.dumps(topo))
        writer.write(buf)
        await writer.drain()

        try:
            prog_version = await read_length_prefixed_async(reader)
        except asyncio.exceptions.IncompleteReadError:
            # Maybe we changed HEALTHCHECK operation ID
            continue

        if not prog_version.startswith(b"simplesync"):
            raise RuntimeError(f"Unknown program running on {host}:{port}: {prog_version!r}")

        version = prog_version.removeprefix(b"simplesync")
        if version != self_version():
            if after_bootstrap:
                raise RuntimeError(
                    f"Unfixable version mismatch between client and server on {host}:{port}: "
                    f"client={self_version()!r}, server={version!r}"
                )

            print(
                f"Detected version mismatch between client and server on {host}:{port}, updating..."
            )

            buf = bytearray()
            buf.extend(ServerOperation.SELF_KILL.to_bytes(8, byteorder="big"))
            write_length_prefixed(buf, pickle.dumps(topo))
            writer.write(buf)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            try:
                assert await read_length_prefixed_async(reader) == b"GOODBYE"
            except EOFError:
                pass

            await asyncio.sleep(0.1)  # seems needed to avoid ConnectionResetError :-/
            await bootstrap(remotes, run_callback)
            after_bootstrap = True
            continue

        return Connection(host=host, port=port, reader=reader, writer=writer, forwards=forwards)

    raise RuntimeError("Failed to bootstrap connection")


async def client(
    *,
    src: str,
    dst: str,
    remotes: list[tuple[str, int]],
    run_callback: Callable[[str, str, str], Awaitable[None]],
    skip_mtime: bool = False,
) -> None:
    print(
        f"{'=' * 10} WARNING {'=' * 10}\n"
        "This is a very simple code upload tool with several major downsides:\n"
        "- It doesn't have a command to wait for sync to complete\n"
        "- It doesn't handle symlinks or permissions\n"
        "- It's not well tested\n"
        "- It doesn't do anything clever for small deltas to large files\n"
        "\n"
        "However, it's got one major upside:\n"
        "- It's fast!\n"
        f"{'=' * 29}\n"
    )

    print(f"Syncing {src} to {dst} on {len(remotes)} remote nodes...\n")

    print("Bootstrapping...")
    ignore_cache = gitignorefile.Cache()
    local_size_mtimes_future = asyncio.get_running_loop().run_in_executor(
        None, collect_file_size_mtimes, src, ignore_cache
    )

    with Timer() as t_bootstrap:
        connections = [await establish_bootstrapped_connection(remotes, run_callback)]

    print(f"Bootstrapped remote daemons in {t_bootstrap}\n")

    # Start running the watcher before the initial sync so we don't miss any changes
    watcher = watchfiles.awatch(src)
    watcher_init = asyncio.ensure_future(anext(watcher))

    try:
        await sync_initial(src, dst, local_size_mtimes_future, connections, skip_mtime=skip_mtime)
        print(f"Watching {src} for changes...\n")

        changes = await watcher_init
        await sync_watcher_changes(src, dst, connections, ignore_cache, changes)

        async for changes in watcher:
            await sync_watcher_changes(src, dst, connections, ignore_cache, changes)
    finally:
        for c in connections:
            c.writer.close()
            await c.writer.wait_closed()


# ==============================
# Benchmark upload
# ==============================


async def benchmark(host: str, port: int) -> None:
    import random

    for i in range(28):
        data = random.randbytes(2**i)

        with Timer(f"{len(data):_} first overall", log_level=0):
            with Timer(f"{len(data):_} open_connection", log_level=0):
                reader, writer = await open_connection(host, port)
            with Timer(f"{len(data):_} send", log_level=0):
                buf = bytearray()
                buf.extend(ServerOperation.BENCHMARK_UPLOAD.to_bytes(8, byteorder="big"))
                write_length_prefixed(buf, data)
                writer.write(buf)
                await writer.drain()
            with Timer(f"{len(data):_} wait for ack", log_level=0):
                value = await read_length_prefixed_async(reader)
                assert int.from_bytes(value, byteorder="big") == len(data)

        with Timer(f"{len(data):_} second overall", log_level=0) as t_overall:
            with Timer(f"{len(data):_} second send", log_level=0):
                writer.write(buf)
                await writer.drain()
            with Timer(f"{len(data):_} second wait for ack", log_level=0):
                value = await read_length_prefixed_async(reader)
                assert int.from_bytes(value, byteorder="big") == len(data)

        with Timer(f"{len(data):_} close", log_level=0):
            writer.close()
            await writer.wait_closed()
        if t_overall.time() > 10:
            break


# ==============================
# Main
# ==============================


def main() -> None:
    set_log_level(1)
    asyncio.run(server())


if __name__ == "__main__":
    main()
