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
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterator

if TYPE_CHECKING:
    import watchfiles
    import zstandard
else:
    deps = ["watchfiles", "zstandard"]
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
    sock.setblocking(False)
    sock.settimeout(10)
    sock.connect((host, port))
    sock.settimeout(None)
    transport, _ = await loop.create_connection(lambda: protocol, sock=sock)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer


# ==============================
# File system helpers
# ==============================


class _Entry:
    __slots__ = ("path", "_cached_stat")

    def __init__(self, path: str) -> None:
        self.path = path
        self._cached_stat: os.stat_result | None = None

    @property
    def stat(self) -> os.stat_result:
        if self._cached_stat is None:
            self._cached_stat = os.lstat(self.path)
        return self._cached_stat

    @property
    def size(self) -> int:
        return self.stat.st_size

    @property
    def mtime(self) -> float:
        return self.stat.st_mtime

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.stat.st_mode)

    @property
    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.stat.st_mode)

    def __reduce__(self) -> tuple[Any, ...]:
        return (_Entry, (self.path,))


def collect_file_size_mtimes(
    path: str, ignore_cache: GitIgnoreCache
) -> dict[str, tuple[int, float]]:
    assert os.path.isabs(path)
    stats: dict[str, tuple[int, float]] = {}
    root = _Entry(path)
    try:
        if not root.is_dir:
            return {".": (root.size, root.mtime)}
    except FileNotFoundError:
        return {}

    cache_ver = 217
    cache_dir = os.path.join(tempfile.gettempdir(), "simple_sync")
    cache_file = f"scan_{hashlib.sha1(path.encode()).hexdigest()}.pkl.zstd"

    scandir_cache: dict[str, tuple[float, list[str]]]
    with Timer("cfsm_cache_load", log_level=1):
        try:
            os.makedirs(cache_dir, exist_ok=True)
            with open(os.path.join(cache_dir, cache_file), "rb") as fr:
                version, scandir_cache = pickle.loads(zstandard.decompress(fr.read()))
            if version != cache_ver:
                scandir_cache = {}
        except Exception:
            scandir_cache = {}

    def _scandir(entry: _Entry) -> list[_Entry]:
        dirname = entry.path
        if dirname in scandir_cache:
            mtime, names = scandir_cache[dirname]
            if mtime == entry.mtime:
                return [_Entry(os.path.join(dirname, f)) for f in names]
        ret = []
        cache_entry = []
        for p in os.scandir(entry.path):
            ret.append(_Entry(p.path))
            cache_entry.append(p.name)
        scandir_cache[dirname] = (entry.mtime, cache_entry)
        return ret

    with Timer("cfsm_scan", log_level=1):
        prefix_len = len(path) + 1
        stack: list[_Entry] = [root]
        while stack:
            item = stack.pop()
            item_is_dir = item.is_dir

            if ignore_cache(item.path, is_dir=item_is_dir):
                continue
            if item_is_dir:
                stack.extend(_scandir(item))
                continue
            if item.is_symlink:
                # TODO: we don't support symlinks
                continue
            stats[item.path[prefix_len:]] = (item.size, item.mtime)

    with Timer("cfsm_cache_dump", log_level=1):
        try:
            with open(os.path.join(cache_dir, cache_file), "wb") as fw:
                fw.write(
                    zstandard.compress(pickle.dumps((cache_ver, scandir_cache)), level=ZSTD_LEVEL)
                )
        except OSError:
            pass
    return stats


def dot_safe_join(base: str, relpath: str) -> str:
    if relpath == ".":
        return base
    return os.path.join(base, relpath)


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
        try:
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
        except Exception as e:
            e.add_note(f"Exception occurred forwarding to {host}:{port}")
            raise

        return response

    with Timer(f"t_forward to {len(topo)} nodes", log_level=1):
        ret = await asyncio.gather(*[forward_one(host, port) for (host, port) in topo])

    return ret


def _perform_op(op: tuple[Any, ...], dst: str) -> None:
    op_type = op[0]
    if op_type == FileOperation.WRITE:
        path = dot_safe_join(dst, op[1])
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
        path = dot_safe_join(dst, op[1])
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
            ignore_cache = GitIgnoreCache()
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
                ret: dict[str, Any] = {}
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


def ops_from_changed_paths(src: str, relpaths: list[str]) -> tuple[list[tuple[Any, ...]], int]:
    def helper(relpath: str) -> tuple[Any, ...] | None:
        return op_from_path(path=dot_safe_join(src, relpath), relpath=relpath)

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

    for op in ops[:10]:
        log(f"{FileOperation(op[0]).name}, {op[1]}", level=1)
    if len(ops) > 10:
        log(f"... and {len(ops) - 10} more", level=1)

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


async def _sync_initial_one(
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
        if n_bytes > 10**9:
            print("(This is a large amount of data, are you syncing the correct locations?)")

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
                _sync_initial_one(
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
    ignore_cache: GitIgnoreCache,
    changes: set[tuple[watchfiles.Change, str]],
) -> None:
    print(f"Detected {len(changes)} changes...")
    t_overall = Timer().start()

    change_by_path: dict[str, watchfiles.Change] = {}
    # changes is unordered and may contain duplicates. We deduplicate, preserving added
    # and modified changes over deleted changes (since we'll find out whether the file exists
    # or not when reading it)
    for change, path in changes:
        if ignore_cache(path, is_dir=False):
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
        topo: TreeTopo = {f: {} for f in forwards}

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
    remote_groups: dict[str, list[tuple[str, int]]],
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

    for group, remotes in remote_groups.items():
        print(f"Syncing {src} to {dst} on {len(remotes)} remote nodes in {group}...")
    print()

    print("Bootstrapping...")
    ignore_cache = GitIgnoreCache()
    local_size_mtimes_future = asyncio.get_running_loop().run_in_executor(
        None, collect_file_size_mtimes, src, ignore_cache
    )

    with Timer() as t_bootstrap:
        connections = await asyncio.gather(
            *[
                establish_bootstrapped_connection(remotes, run_callback)
                for _, remotes in remote_groups.items()
            ]
        )

    print(f"Bootstrapped remote daemons in {t_bootstrap}\n")

    # Start running the watcher before the initial sync so we don't miss any changes
    # (also note watchfiles does a little bit of filtering itself that should usually be redundant
    # with our gitignore filtering)
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
# Gitignore
# ==============================


# Based on:
# https://git-scm.com/docs/gitignore
# https://github.com/excitoon/gitignorefile
# https://github.com/mherrmann/gitignore_parser
# https://github.com/cpburnz/python-pathspec


class GitIgnoreCache:
    def __init__(self) -> None:
        self._gitignores: dict[tuple[str, ...], list[GitIgnore]] = {}

    def __call__(self, path: str | _PathParts, is_dir: bool) -> bool:
        """Checks whether the specified path is ignored."""
        assert isinstance(path, str)
        path = _PathParts.from_str(path)

        add_to_children: list[tuple[_PathParts, list[GitIgnore], list[_PathParts]]] = []
        copy_from_parent: list[_PathParts] = []
        for parent in path.parents():
            if parent.parts in self._gitignores:
                break

            gitignores = []
            parent_fspath = parent.fspath()
            for name in [".gitignore", ".git/info/exclude"]:
                ignore_path = os.path.join(parent_fspath, name)
                if os.path.isfile(ignore_path):
                    with open(ignore_path) as ignore_file:
                        gitignore = GitIgnore.parse(ignore_file.read(), parent)
                    if gitignore:
                        gitignores.append(gitignore)

            if gitignores:
                add_to_children.append((parent, gitignores, copy_from_parent))
                copy_from_parent = []
            else:
                copy_from_parent.append(parent)
        else:
            parent = _PathParts(tuple())  # null path
            self._gitignores[()] = []

        for plain_child in copy_from_parent:
            assert plain_child.parts not in self._gitignores
            self._gitignores[plain_child.parts] = self._gitignores[parent.parts]

        for parent, _, copy_from_parent in reversed(add_to_children):
            assert parent.parts not in self._gitignores
            self._gitignores[parent.parts] = self._gitignores[parent.parts[:-1]].copy()

            for source_parent, gitignores, _ in reversed(add_to_children):
                self._gitignores[parent.parts].extend(gitignores)
                if source_parent == parent:
                    break

            self._gitignores[parent.parts].reverse()

            for plain_child in copy_from_parent:
                assert plain_child.parts not in self._gitignores
                self._gitignores[plain_child.parts] = self._gitignores[parent.parts]

        for m in self._gitignores[path.parts[:-1]]:  # noqa: SIM110
            if m.match(path, is_dir=is_dir):
                return True
        return False


_path_split: Callable[[str], list[str]]
if os.altsep is not None:
    _all_seps_pattern = re.compile(f"[{re.escape(os.sep)}{re.escape(os.altsep)}]")
    _path_split = lambda path: re.split(_all_seps_pattern, path)
else:
    _path_split = lambda path: path.split(os.sep)


class _PathParts:
    __slots__ = "parts"

    def __init__(self, parts: tuple[str, ...]) -> None:
        self.parts = parts

    @classmethod
    def from_str(cls, path: str) -> _PathParts:
        return cls(tuple(_path_split(path)))

    def relpath_posix(self, base_path: _PathParts) -> str | None:
        if self.parts[: len(base_path.parts)] != base_path.parts:
            return None
        return "/".join(self.parts[len(base_path.parts) :])

    def parents(self) -> Iterator[_PathParts]:
        for i in range(len(self.parts) - 1, 0, -1):
            yield _PathParts(self.parts[:i])

    def dirname(self) -> _PathParts:
        return _PathParts(self.parts[:-1])

    def fspath(self) -> str:
        return os.sep.join(self.parts) if self.parts != ("",) else os.sep

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.parts!r})"


def _rule_from_pattern(pattern: str) -> tuple[str, bool] | None:
    """Returns a tuple of (regexp, negation) for a `.gitignore` match pattern."""

    # A blank line matches no files, so it can serve as a separator for readability
    # A line starting with # serves as a comment
    if not pattern.lstrip() or pattern.lstrip().startswith("#"):
        return None

    # Put a backslash ("\") in front of the first hash for patterns that begin with a hash
    if pattern.startswith("\\#"):
        pattern = pattern[1:]

    # Trailing spaces are ignored unless they are quoted with backslash ("\")
    while pattern.endswith(" ") and not pattern.endswith("\\ "):
        pattern = pattern[:-1]
    if pattern.endswith("\\ "):
        pattern = pattern[:-2] + " "

    # An optional prefix "!" which negates the pattern
    if pattern.startswith("!"):
        negation = True
        pattern = pattern[1:]
    else:
        negation = False

    # If there is a separator at the beginning or middle (or both) of the pattern, then the
    # pattern is relative to the directory level of the particular .gitignore file itself
    anchored = "/" in pattern[:-1]
    if pattern.startswith("/"):
        pattern = pattern[1:]
    if pattern.startswith("**"):
        pattern = pattern[2:]
        if pattern.startswith("/"):
            pattern = pattern[1:]
        anchored = False

    assert pattern
    n = len(pattern)

    def callback(m: re.Match[str]) -> str:
        c = m.group(0)
        if c == "/**/":
            return "(?:/|/.+/)"  # a/**/b matches a/b
        if c == "**":
            if m.start() == 0 or m.end() == n:
                return ".*"
            return "[^/]*"  # "other consecutive asterisks"
        if c == "*":
            return "[^/]*"
        if c == "?":
            return "[^/]"
        if c.startswith("[") and c.endswith("]"):
            stuff = c[1:-1]
            if not stuff:
                return "(?!)"  # empty range: never match
            stuff = stuff.replace("\\", "\\\\")
            if stuff == "!":
                return "."  # negated empty range: match any character
            if stuff[0] == "!":
                stuff = "^" + stuff[1:]
            elif stuff[0] in ("^", "["):
                stuff = "\\" + stuff
            return f"[{stuff}]"
        return re.escape(c)

    regexp = re.sub(r"/\*\*/|\*\*|\*|\?|\[.*\]|.", callback, pattern)
    if not anchored:
        regexp = "(?:^|.+/)" + regexp
    if pattern.endswith("/"):
        regexp += "(?:.+)?$"
    else:
        regexp += "(?:/.*)?$"

    return regexp, negation


class GitIgnore:
    def __init__(
        self, rules: list[tuple[re.Pattern[str], bool]], base_path: str | _PathParts
    ) -> None:
        self._rules = rules
        if isinstance(base_path, str):
            base_path = _PathParts.from_str(base_path)
        self._base_path = base_path

    @classmethod
    def parse(cls, contents: str, dirname: str | _PathParts) -> GitIgnore | None:
        rules: list[tuple[str, bool]] = []
        for line in contents.splitlines():
            if rule := _rule_from_pattern(line):
                rules.append(rule)
                pass
        if not rules:
            return None

        batched_rules: list[tuple[re.Pattern[str], bool]] = []
        current_regexp = [rules[0][0]]
        current_negation = rules[0][1]
        for regexp, negation in rules[1:]:
            if negation == current_negation:
                current_regexp.append(regexp)
            else:
                batched_rules.append((re.compile("|".join(current_regexp)), current_negation))
                current_regexp = [regexp]
                current_negation = negation
        batched_rules.append((re.compile("|".join(current_regexp)), current_negation))
        return GitIgnore(batched_rules, dirname)

    def match(self, path: str | _PathParts, is_dir: bool) -> bool:
        if isinstance(path, str):
            path = _PathParts.from_str(path)
        relpath = path.relpath_posix(self._base_path)
        if relpath is None:
            return False
        if is_dir and not relpath.endswith("/"):
            relpath += "/"
        matched = False
        for pattern, negation in self._rules:
            if pattern.fullmatch(relpath):
                matched = not negation
        return matched


# ==============================
# Main
# ==============================


def main() -> None:
    set_log_level(1)
    asyncio.run(server())


if __name__ == "__main__":
    main()
