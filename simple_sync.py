#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import enum
import functools
import hashlib
import importlib
import marshal
import math
import os
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
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterator, Protocol

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


def exc_repr(e: BaseException) -> str:
    ret = f"{type(e).__name__}: {e}"
    if getattr(e, "__notes__", None):
        ret += f" {e.__notes__}"
    return ret


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
CLIENT_TIMEOUT = 30


async def open_connection(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=STREAM_READER_LIMIT, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    sock = get_socket()
    sock.setblocking(False)
    sock.settimeout(2)
    sock.connect((host, port))
    sock.settimeout(CLIENT_TIMEOUT - 1)
    transport, _ = await loop.create_connection(lambda: protocol, sock=sock)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer


class ConnectionPool:
    def __init__(self) -> None:
        self.conns: dict[tuple[str, int], tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}

    async def acquire(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        key = (host, port)
        if key in self.conns:
            return self.conns.pop(key)
        return await open_connection(host, port)

    def release(
        self, host: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        key = (host, port)
        if key in self.conns:
            writer.close()
            return
        self.conns[key] = (reader, writer)


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
    def mode(self) -> int:
        return self.stat.st_mode

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.stat.st_mode)

    @property
    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.stat.st_mode)

    def __reduce__(self) -> tuple[Any, ...]:
        raise NotImplementedError


def collect_file_size_mtime_modes(
    path: str, ignore_cache: GitIgnoreCache
) -> dict[str, tuple[int, float, int]]:
    assert os.path.isabs(path)

    # Important to normalise, since we do some string manipulation on paths in this function
    path = os.path.normpath(path)

    stats: dict[str, tuple[int, float, int]] = {}
    root = _Entry(path)
    try:
        if not root.is_dir:
            return {".": (root.size, root.mtime, root.mode)}
    except FileNotFoundError:
        return {}

    cache_ver = 217
    cache_dir = os.path.join(tempfile.gettempdir(), "simple_sync")
    cache_file = f"scan_{hashlib.sha1(path.encode()).hexdigest()}.marshal.zstd"

    scandir_cache: dict[str, tuple[float, list[str]]]
    with Timer("cfsm_cache_load", log_level=1):
        try:
            os.makedirs(cache_dir, exist_ok=True)
            with open(os.path.join(cache_dir, cache_file), "rb") as fr:
                version, scandir_cache = marshal.loads(zstandard.decompress(fr.read()))
            if version != cache_ver:
                scandir_cache = {}
        except Exception:
            scandir_cache = {}

    def _scandir(entry: _Entry) -> list[_Entry]:
        dirname = entry.path
        if dirname in scandir_cache:
            mtime, names = scandir_cache[dirname]
            if mtime == entry.mtime:
                # return [_Entry(os.path.join(dirname, f)) for f in names]
                return [_Entry(dirname + os.sep + f) for f in names]
        ret = []
        cache_entry = []
        for p in os.scandir(entry.path):
            item = _Entry(p.path)
            # It's not correct to cache the results post ignore_cache-filtering. If something goes
            # from gitignored right now to not gitignored later, we'll incorrectly not collect
            # it later (if parent mtime doesn't change).
            if ignore_cache(item.path, is_dir=item.is_dir):
                continue
            ret.append(item)
            cache_entry.append(p.name)
        scandir_cache[dirname] = (entry.mtime, cache_entry)
        return ret

    with Timer("cfsm_scan", log_level=1):
        prefix_len = len(path) + 1
        stack: list[_Entry] = [root]
        while stack:
            item = stack.pop()
            try:
                item_is_dir = item.is_dir
            except FileNotFoundError:
                # It's possible but rare that there's some raciness, especially if mtime resolution
                # in the cache is low
                continue
            # The correct thing to do is call ignore_cache here (and remove it above). If something
            # goes from not gitignored at cache time to gitignored right now, we'll incorrectly
            # return it (if parent mtime doesn't change). But this way it's so much faster!
            # if ignore_cache(item.path, is_dir=item_is_dir):
            #     continue
            if item_is_dir:
                stack.extend(_scandir(item))
                continue

            # assert item.path[prefix_len - 1] == os.sep
            stats[item.path[prefix_len:]] = (item.size, item.mtime, item.mode)

    with Timer("cfsm_cache_dump", log_level=1):
        try:
            with open(os.path.join(cache_dir, cache_file), "wb") as fw:
                fw.write(
                    zstandard.compress(marshal.dumps((cache_ver, scandir_cache)), level=ZSTD_LEVEL)
                )
        except OSError:
            pass
    return stats


def hash_path(path: str) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        try:
            st = os.lstat(path)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            try:
                link_target = os.readlink(path)
                h = hashlib.sha1()
                h.update(b"symlink\x00")
                h.update(link_target.encode(errors="surrogateescape"))
                return h.digest()
            except OSError:
                return None
        return None
    else:
        h = hashlib.sha1()
        try:
            f = os.fdopen(fd, "rb", buffering=0)
        except OSError:
            os.close(fd)
            return None
        try:
            with f:
                while True:
                    chunk = f.read(2**20)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.digest()
        except OSError:
            return None


def _hash_paths(base: str, relpaths: list[str]) -> dict[str, bytes | None]:
    def helper(relpath: str) -> tuple[str, bytes | None]:
        return relpath, hash_path(dot_safe_join(base, relpath))

    ret: dict[str, bytes | None] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for relpath, digest in pool.map(helper, relpaths):
            ret[relpath] = digest
    return ret


def write_atomic_no_follow(path: str, contents: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
    tmp_path = path + ".shrek.tmp"
    fd = os.open(tmp_path, flags)
    try:
        os.write(fd, contents)
    finally:
        os.close(fd)
    os.replace(tmp_path, path)


def dot_safe_join(base: str, relpath: str) -> str:
    if relpath == ".":
        return base
    return os.path.join(base, relpath)


def portable_mode_key(mode: int) -> int:
    if stat.S_ISLNK(mode):
        # symlink permissions are not portable
        return stat.S_IFMT(mode)
    return mode


# ==============================
# Server definition
# ==============================


class ServerOperation(enum.IntEnum):
    HEALTHCHECK = 17
    FILE_BATCH = 5
    LIST_SIZES_SOME_MTIMES = 7
    LIST_HASHES = 29
    REVERSE_SYNC = 23
    SELF_KILL = 11
    BENCHMARK_UPLOAD = 13
    SERVER_EVENTS = 19


class FileOperation(enum.IntEnum):
    WRITE = 43
    DELETE = 44
    SYMLINK = 45


TreeTopo = dict[tuple[str, int], "TreeTopo"]


async def forward_to_topo(
    pool: ConnectionPool, topo: TreeTopo, op: ServerOperation, payloads: list[bytes]
) -> list[bytes]:
    async def forward_one(host: str, port: int) -> bytes:
        try:
            reader, writer = await pool.acquire(host, port)
            buf = bytearray()
            buf.extend(op.to_bytes(8, byteorder="big"))
            for payload in payloads:
                write_length_prefixed(buf, payload)
            write_length_prefixed(buf, marshal.dumps(topo[(host, port)]))

            writer.write(buf)
            await writer.drain()

            response = await read_length_prefixed_async(reader)
            pool.release(host, port, reader, writer)
        except Exception as e:
            e.add_note(f"Exception occurred forwarding to {host}:{port}")
            raise

        return response

    with Timer(f"t_forward {op.name} to {len(topo)} nodes", log_level=1):
        ret = await asyncio.gather(*[forward_one(host, port) for (host, port) in topo])

    return ret


def _make_dirs_leading_to_path(path: str) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except FileExistsError:
        try:
            os.remove(path)
        except FileNotFoundError:
            os.remove(os.path.dirname(path))  # can happen with symlinks
        os.makedirs(os.path.dirname(path), exist_ok=True)


def _perform_op(op: tuple[Any, ...], dst: str) -> None:
    op_type = op[0]
    if op_type == FileOperation.WRITE:
        path = dot_safe_join(dst, op[1])
        contents = op[2]
        mode = op[3]
        _make_dirs_leading_to_path(path)
        log(f"Writing {len(contents)} bytes to {path}", level=2)
        try:
            write_atomic_no_follow(path, contents)
        except IsADirectoryError:
            shutil.rmtree(path, ignore_errors=True)
            write_atomic_no_follow(path, contents)
        os.chmod(path, mode, follow_symlinks=False)
    elif op_type == FileOperation.DELETE:
        path = dot_safe_join(dst, op[1])
        log(f"Deleting {path}", level=2)
        try:
            os.remove(path)
        except FileNotFoundError:
            # If the file is not found, we've already done our job
            pass
        except IsADirectoryError:
            # If we e.g. renamed a directory, this will be a delete op for the old name
            # Note we should process deletes before writes
            shutil.rmtree(path, ignore_errors=True)
    elif op_type == FileOperation.SYMLINK:
        path = dot_safe_join(dst, op[1])
        target = op[2]
        _make_dirs_leading_to_path(path)
        try:
            os.symlink(target, path)
        except FileExistsError:
            try:
                os.remove(path)
            except (IsADirectoryError, PermissionError):
                shutil.rmtree(path, ignore_errors=True)
            os.symlink(target, path)
    else:
        raise ValueError(f"Unknown file operation: {op}")


def _perform_ops(ops: list[tuple[Any, ...]], dst: str) -> None:
    # If you're tempted to parallelise this, make sure to handle deletes first

    exc = None  # do our best to perform all ops, even if some fail
    for op in ops:
        try:
            _perform_op(op, dst)
        except Exception as e:
            log(f"Error performing op {op[0]}: {exc_repr(e)}", level=0)
            import traceback

            traceback.print_exc()
            exc = e
    if exc:
        try:
            raise exc
        finally:
            del exc


class Handler:
    def __init__(
        self, server: Server, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.server = server
        self.reader = reader
        self.writer = writer
        self.pool = ConnectionPool()
        self.version = self_version()

    async def healthcheck(self) -> None:
        topo = marshal.loads(await read_length_prefixed_async(self.reader))

        attempt = 0
        start_t = time.perf_counter()
        while True:
            attempt += 1
            try:
                forward_responses = await forward_to_topo(
                    self.pool, topo, ServerOperation.HEALTHCHECK, []
                )
                break
            except ConnectionRefusedError as e:
                log(f"Connection refused when healthchecking, retrying: {exc_repr(e)}", level=1)
                await asyncio.sleep(0.1)
            except Exception as e:
                log(f"Exception when healthchecking: {exc_repr(e)}", level=0)
                await asyncio.sleep(0.1)

            if attempt >= 3 and time.perf_counter() - start_t > 5:
                forward_responses = [b"simplesyncunhealthy"]
                break

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
            dst, ops = marshal.loads(zstandard.decompress(dst_ops_payload))
            log(f"dst: {dst}", level=1)
            log(f"num ops: {len(ops)}", level=1)

        with Timer("t_topo", log_level=1):
            topo = marshal.loads(await read_length_prefixed_async(self.reader))
            log(f"topo: {topo}", level=2)

        forward_task = asyncio.create_task(
            forward_to_topo(self.pool, topo, ServerOperation.FILE_BATCH, [dst_ops_payload])
        )

        with Timer("t_perform_ops", log_level=1):
            await asyncio.get_running_loop().run_in_executor(None, _perform_ops, ops, dst)

        with Timer("t_forward_latency", log_level=1):
            try:
                forward_responses = await forward_task
            except Exception as e:
                log(f"Exception when forwarding file batch: {exc_repr(e)}", level=0)
                forward_responses = [b"FAILED"]

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

        self.server.sync_events[dst] = time.time_ns()

    async def list_sizes_some_mtimes(self) -> None:
        with Timer("t_payload_load", log_level=1):
            dst = marshal.loads(await read_length_prefixed_async(self.reader))
            need_mtimes = marshal.loads(await read_length_prefixed_async(self.reader))
            topo = marshal.loads(await read_length_prefixed_async(self.reader))
            log(f"topo: {topo}", level=2)

        with Timer("t_setup", log_level=1):
            ignore_cache = GitIgnoreCache()
            file_size_mtime_modes_future = asyncio.get_running_loop().run_in_executor(
                None, collect_file_size_mtime_modes, dst, ignore_cache
            )
            forward_task = asyncio.create_task(
                forward_to_topo(
                    self.pool,
                    topo,
                    ServerOperation.LIST_SIZES_SOME_MTIMES,
                    # need_mtimes=False
                    [marshal.dumps(dst), marshal.dumps(False)],
                )
            )

        with Timer("t_file_sizes_latency", log_level=1):
            file_size_mtime_modes = await file_size_mtime_modes_future

        with Timer("t_file_sizes_overhead", log_level=1):
            file_size_modes = {k: (v[0], v[2]) for k, v in file_size_mtime_modes.items()}

        with Timer("t_forward_latency", log_level=1):
            forward_responses = await forward_task

        with Timer("t_forward_combine", log_level=1):
            for forward_response in forward_responses:
                remote_size_modes = marshal.loads(zstandard.decompress(forward_response))
                # symmetric difference of items (missing keys or mismatched values)
                for relpath, _ in file_size_modes.items() ^ remote_size_modes.items():
                    file_size_modes[relpath] = (-1, 0)  # something that will never match client

        with Timer("t_maybe_mtimes", log_level=1):
            if need_mtimes:
                # while we reduce sizes, mtimes are only from one node
                ret: dict[str, Any] = {}
                for relpath, (size, _) in file_size_modes.items():
                    if size == -1:
                        ret[relpath] = (-1, 0, 0)
                    else:
                        size_mtime_mode = file_size_mtime_modes[relpath]
                        ret[relpath] = (size, size_mtime_mode[1], size_mtime_mode[2])
            else:
                ret = file_size_modes

        with Timer("t_dump", log_level=1):
            response_payload = zstandard.compress(marshal.dumps(ret), level=ZSTD_LEVEL)
            log(f"response payload size: {len(response_payload):_} bytes", level=1)

        with Timer("t_resp", log_level=1):
            buf = bytearray()
            write_length_prefixed(buf, response_payload)
            self.writer.write(buf)
            await self.writer.drain()

    async def list_hashes(self) -> None:
        with Timer("t_payload_load", log_level=1):
            dst = marshal.loads(await read_length_prefixed_async(self.reader))
            relpaths = marshal.loads(await read_length_prefixed_async(self.reader))
            topo = marshal.loads(await read_length_prefixed_async(self.reader))
            log(f"topo: {topo}", level=2)

        with Timer("t_setup", log_level=1):
            hash_future = asyncio.get_running_loop().run_in_executor(
                None, _hash_paths, dst, relpaths
            )
            forward_task = asyncio.create_task(
                forward_to_topo(
                    self.pool,
                    topo,
                    ServerOperation.LIST_HASHES,
                    [marshal.dumps(dst), marshal.dumps(relpaths)],
                )
            )

        with Timer("t_hashes_latency", log_level=1):
            local_hashes = await hash_future

        with Timer("t_forward_latency", log_level=1):
            forward_responses = await forward_task

        with Timer("t_forward_combine", log_level=1):
            for forward_response in forward_responses:
                remote_hashes = marshal.loads(zstandard.decompress(forward_response))
                # symmetric difference of items (missing keys or mismatched values)
                for relpath, _ in local_hashes.items() ^ remote_hashes.items():
                    local_hashes[relpath] = None

        with Timer("t_dump", log_level=1):
            response_payload = zstandard.compress(marshal.dumps(local_hashes), level=ZSTD_LEVEL)
            log(f"response payload size: {len(response_payload):_} bytes", level=1)

        with Timer("t_resp", log_level=1):
            buf = bytearray()
            write_length_prefixed(buf, response_payload)
            self.writer.write(buf)
            await self.writer.drain()

    async def reverse_sync(self) -> None:
        with Timer("t_payload_load", log_level=1):
            src = marshal.loads(await read_length_prefixed_async(self.reader))
            dst = marshal.loads(await read_length_prefixed_async(self.reader))
            once = marshal.loads(await read_length_prefixed_async(self.reader))

        ignore_cache = GitIgnoreCache()
        local_size_mtime_modes_future = asyncio.get_running_loop().run_in_executor(
            None, collect_file_size_mtime_modes, src, ignore_cache
        )

        connections = [
            TopoConnection(
                conn=RawConnection(reader=self.reader, writer=self.writer),
                leader=("localhost", PORT),
                forwards=[],
            )
        ]

        await _client_bootstrapped(
            src=src,
            dst=dst,
            skip_mtime=False,
            description="reverse sync",
            once=once,
            on_local_change_event=None,
            ignore_cache=ignore_cache,
            local_size_mtime_modes_future=local_size_mtime_modes_future,
            connections=connections,
        )

    async def self_kill(self) -> None:
        log("Received self-kill signal...", level=0)

        topo = marshal.loads(await read_length_prefixed_async(self.reader))
        try:
            forward_responses = await forward_to_topo(
                self.pool, topo, ServerOperation.SELF_KILL, []
            )
        except Exception as e:
            log(f"Exception when forwarding self-kill: {exc_repr(e)}", level=0)
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

    async def server_events(self) -> None:
        events = {
            "num_connections": len(self.server.handlers),
            "sync_events": self.server.sync_events,
        }
        buf = bytearray()
        write_length_prefixed(buf, marshal.dumps(events))
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
                    f"{self.writer._transport.get_extra_info('peername')} "  # type: ignore[attr-defined]
                    f"at {time.strftime('%H:%M:%S')}",
                    level=0,
                )

                if operation == ServerOperation.HEALTHCHECK:
                    await self.healthcheck()
                    continue

                if operation == ServerOperation.FILE_BATCH:
                    await self.file_batch()
                    continue

                if operation == ServerOperation.LIST_SIZES_SOME_MTIMES:
                    await self.list_sizes_some_mtimes()
                    continue

                if operation == ServerOperation.LIST_HASHES:
                    await self.list_hashes()
                    continue

                if operation == ServerOperation.REVERSE_SYNC:
                    await self.reverse_sync()
                    continue

                if operation == ServerOperation.SELF_KILL:
                    await self.self_kill()
                    continue

                if operation == ServerOperation.BENCHMARK_UPLOAD:
                    await self.benchmark_upload()
                    continue

                if operation == ServerOperation.SERVER_EVENTS:
                    await self.server_events()
                    continue

                raise AssertionError(f"Unhandled server operation: {operation}")

        except ConnectionError as e:
            log(f"Connection closed by client: {exc_repr(e)}", level=0)
        except Exception as e:
            log(f"Unexpected error: {exc_repr(e)}", level=0)
            import traceback

            traceback.print_exc()
        finally:
            self.server.handlers.remove(self)


class Server:
    def __init__(self) -> None:
        self.handlers: set[Handler] = set()
        self.sync_events: dict[str, float] = {}

    async def handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handler = Handler(self, reader, writer)
        self.handlers.add(handler)
        await handler.handle()


async def server() -> None:
    sock = get_socket()

    sock.bind(("0.0.0.0", PORT))
    sock.settimeout(None)

    s = Server()
    server = await asyncio.start_server(s.handler, sock=sock, limit=STREAM_READER_LIMIT)
    async with server:
        await server.serve_forever()


@functools.lru_cache()
def self_version() -> bytes:
    with open(__file__, "rb") as f:
        return hashlib.md5(f.read()).hexdigest().encode()


# ==============================
# Client
# ==============================


class Connection(Protocol):
    @property
    def reader(self) -> asyncio.StreamReader: ...
    @property
    def writer(self) -> asyncio.StreamWriter: ...
    async def close(self) -> None: ...


@dataclass
class RawConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    @classmethod
    async def connect(cls, remote: tuple[str, int]) -> RawConnection:
        host, port = remote
        reader, writer = await open_connection(host, port)
        return cls(reader, writer)

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()


@dataclass
class TopoGroup:
    """A TopoGroup is a set of remotes that can connect directly to each other."""

    name: str
    # remotes is a list of (host, port) tuples
    remotes: list[tuple[str, int]]
    # connection_maker is a function that returns a Connection from the client to
    # a given (host, port) remote, e.g. RawConnection.connect
    connection_maker: Callable[[tuple[str, int]], Awaitable[Connection]]


@dataclass
class TopoConnection:
    conn: Connection
    leader: tuple[str, int]
    forwards: list[tuple[str, int]]

    @functools.cached_property
    def leader_str(self) -> str:
        return f"{self.leader[0]}:{self.leader[1]}"

    @property
    def reader(self) -> asyncio.StreamReader:
        return self.conn.reader

    @property
    def writer(self) -> asyncio.StreamWriter:
        return self.conn.writer

    async def close(self) -> None:
        await self.conn.close()

    @classmethod
    async def connect(cls, group: TopoGroup) -> TopoConnection:
        leader, *forwards = group.remotes
        conn = await group.connection_maker(leader)
        return cls(conn, leader, forwards)

    def num_nodes(self) -> int:
        return len(self.forwards) + 1

    @functools.cached_property
    def flat_topo(self) -> TreeTopo:
        return {f: {} for f in self.forwards}

    @property
    def maybe_l2_topo(self) -> TreeTopo:
        # magic number comes from benchmarking
        if len(self.forwards) < 72:
            return self.flat_topo
        return self.l2_topo

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


def op_from_path(*, path: str, relpath: str) -> list[tuple[Any, ...]]:
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            link_target = os.readlink(path)
            return [(FileOperation.SYMLINK.value, relpath, link_target)]

        if stat.S_ISDIR(st.st_mode):
            # collect_file_size_mtime_modes only deals with files, but it's possible to get directories
            # from the file watching loop. In practice, this comes up if a directory was renamed.
            # TODO: this is a little sketchy, doesn't account for gitignore, isn't parallel
            ret = []
            for root, _, files in os.walk(path):
                for file in files:
                    subpath = os.path.join(root, file)
                    ret.extend(
                        op_from_path(
                            path=subpath,
                            relpath=os.path.join(relpath, os.path.relpath(subpath, start=path)),
                        )
                    )
            return ret

        with open(path, "rb", buffering=0) as f:
            contents = f.read()
        if len(contents) >= 2**31:
            raise RuntimeError(f"{relpath} is too large to sync")

        mode = stat.S_IMODE(st.st_mode)

        return [(FileOperation.WRITE.value, relpath, contents, mode)]
    except FileNotFoundError:
        return [(FileOperation.DELETE.value, relpath)]


def ops_from_changed_paths(src: str, relpaths: list[str]) -> tuple[list[tuple[Any, ...]], int]:
    def helper(relpath: str) -> list[tuple[Any, ...]]:
        return op_from_path(path=dot_safe_join(src, relpath), relpath=relpath)

    ops = []
    n_bytes = 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        for some_ops in pool.map(helper, relpaths):
            for op in some_ops:
                if op is None:
                    continue
                if op[0] == FileOperation.WRITE.value:
                    assert isinstance(op[2], bytes)
                    n_bytes += len(op[2])
                ops.append(op)

    return ops, n_bytes


async def sync_ops(dst: str, ops: list[tuple[Any, ...]], connections: list[TopoConnection]) -> None:
    if not ops:
        return

    for op in ops[:10]:
        log(f"{FileOperation(op[0]).name}, {op[1]}", level=1)
    if len(ops) > 10:
        log(f"... and {len(ops) - 10} more", level=1)

    batches = []
    current_batch = []
    current_bytes = 0
    total_bytes = 0
    for op in ops:
        if op[0] != FileOperation.WRITE.value:
            current_batch.append(op)
            continue
        if current_bytes + len(op[2]) > 25 * 10**6:  # 25 MB
            batches.append((current_bytes, current_batch))
            total_bytes += current_bytes
            current_batch = [op]
            current_bytes = len(op[2])
            continue
        current_batch.append(op)
        current_bytes += len(op[2])

    assert current_batch
    batches.append((current_bytes, current_batch))
    total_bytes += current_bytes

    del ops

    sent_bytes = 0
    for i, (n_bytes, batch) in enumerate(batches):
        with Timer("t_dump", log_level=1):
            payload = zstandard.compress(marshal.dumps((dst, batch)), level=ZSTD_LEVEL)
            log(f"ops payload size: {len(payload):_} bytes", level=1)

        with Timer("t_write", log_level=1):
            buf = bytearray()
            buf.extend(ServerOperation.FILE_BATCH.to_bytes(8, byteorder="big"))
            write_length_prefixed(buf, payload)
            for c in connections:
                c.writer.write(buf)
                topobuf = bytearray()
                # flat topo seems fine for most payload sizes, keep it simple and low latency
                write_length_prefixed(topobuf, marshal.dumps(c.maybe_l2_topo))
                c.writer.write(topobuf)

        with Timer("t_drain", log_level=1):
            await asyncio.gather(*[c.writer.drain() for c in connections])

        sent_bytes += n_bytes
        if i < len(batches) - 1:
            print(f"Sent {sent_bytes:_} bytes, {total_bytes - sent_bytes:_} bytes remaining...")

    for _ in range(len(batches)):
        with Timer("t_resp", log_level=1):
            try:
                responses = await asyncio.wait_for(
                    asyncio.gather(*[read_length_prefixed_async(c.reader) for c in connections]),
                    timeout=CLIENT_TIMEOUT,
                )
            except asyncio.TimeoutError as e:
                e.add_note("Timed out, likely due to slow network.")
                raise
            if not all(response == b"SYNCED" for response in responses):
                raise RuntimeError("Failed to sync, check server side logs")


async def _sync_initial_one(
    src: str,
    dst: str,
    local_size_mtime_modes_future: asyncio.Future[dict[str, tuple[int, float, int]]],
    connection: TopoConnection,
    skip_mtime: bool,
    verbose: bool,
) -> tuple[int, int]:
    c = connection

    with Timer("t_read_list", log_level=1):
        payload = await read_length_prefixed_async(c.reader)
        log(f"list payload size: {len(payload):_} bytes", level=1)

    with Timer("t_load", log_level=1):
        remote_size_mtime_modes = marshal.loads(zstandard.decompress(payload))
        assert isinstance(remote_size_mtime_modes, dict)
        del payload

    with Timer("t_local_sizes_latency", log_level=1):
        local_size_mtime_modes = await local_size_mtime_modes_future
        if verbose:
            print("Finished local listing, waiting for remote...")

    with Timer("t_local_diff", log_level=1):
        delete_ops = []
        relpaths_changed = []
        relpaths_maybe_changed = []
        for relpath, (size, mtime, mode) in local_size_mtime_modes.items():
            if relpath not in remote_size_mtime_modes:
                relpaths_changed.append(relpath)
                continue
            if size != remote_size_mtime_modes[relpath][0]:
                relpaths_changed.append(relpath)
                continue
            if (mode != remote_size_mtime_modes[relpath][2]) and (
                portable_mode_key(mode) != portable_mode_key(remote_size_mtime_modes[relpath][2])
            ):
                relpaths_changed.append(relpath)
                continue
            if mtime > remote_size_mtime_modes[relpath][1]:
                relpaths_maybe_changed.append(relpath)
                continue
        for relpath in remote_size_mtime_modes.keys() - local_size_mtime_modes.keys():
            delete_ops.append((FileOperation.DELETE.value, relpath))

    with Timer("t_local_ops", log_level=1):
        write_ops, n_bytes = ops_from_changed_paths(src=src, relpaths=relpaths_changed)
        ops = delete_ops + write_ops

    if ops and verbose:
        print(f"Finished remote listing, {len(ops)} files and {n_bytes:_} bytes to sync...")
        if n_bytes > 10**9:
            print("(This is a large amount of data, are you syncing the correct locations?)")

    total_num_ops = len(ops)
    total_n_bytes = n_bytes
    await sync_ops(dst=dst, ops=ops, connections=[c])

    if skip_mtime:
        return total_num_ops, total_n_bytes

    maybe_changed_bytes = sum(
        local_size_mtime_modes[relpath][0] for relpath in relpaths_maybe_changed
    )
    use_hashes = maybe_changed_bytes > 25 * 10**6  # 25 MB
    if use_hashes:
        if verbose:
            print(
                f"The mtime-based sync would send "
                f"{len(relpaths_maybe_changed)} files and {maybe_changed_bytes:_} bytes; "
                "filtering by hashes first..."
            )

        local_hashes_future = asyncio.get_running_loop().run_in_executor(
            None, _hash_paths, src, relpaths_maybe_changed
        )

        with Timer("t_req_hashes", log_level=1):
            buf = bytearray()
            buf.extend(ServerOperation.LIST_HASHES.to_bytes(8, byteorder="big"))
            write_length_prefixed(buf, marshal.dumps(dst))
            write_length_prefixed(buf, marshal.dumps(relpaths_maybe_changed))
            # l2_topo helps here since there's a reduction involved
            write_length_prefixed(buf, marshal.dumps(connection.l2_topo))
            connection.writer.write(buf)
            await connection.writer.drain()

            payload = await read_length_prefixed_async(connection.reader)
            log(f"hash list payload size: {len(payload):_} bytes", level=1)

        with Timer("t_load_hashes", log_level=1):
            remote_hashes = marshal.loads(zstandard.decompress(payload))
            assert isinstance(remote_hashes, dict)

        with Timer("t_local_hashes_latency", log_level=1):
            local_hashes = await local_hashes_future

        relpaths_mtime = []
        for relpath in relpaths_maybe_changed:
            local_hash = local_hashes.get(relpath)
            remote_hash = remote_hashes.get(relpath)
            if local_hash is None or remote_hash is None or local_hash != remote_hash:
                relpaths_mtime.append(relpath)
    else:
        relpaths_mtime = relpaths_maybe_changed

    with Timer("t_local_ops_mtime", log_level=1):
        ops, n_bytes = ops_from_changed_paths(src=src, relpaths=relpaths_mtime)

    if ops and verbose:
        sync_label = "mtime-based sync"
        if use_hashes:
            sync_label = "mtime-based sync post hash filtering"
        print(
            f"Finished size-based sync, now doing {sync_label} "
            "(use --skip-mtime to dangerously not do this); "
            f"{len(ops)} files and {n_bytes:_} bytes to sync..."
        )

    total_num_ops += len(ops)
    total_n_bytes += n_bytes
    await sync_ops(dst=dst, ops=ops, connections=[c])

    return total_num_ops, total_n_bytes


async def sync_initial(
    src: str,
    dst: str,
    local_size_mtime_modes_future: asyncio.Future[dict[str, tuple[int, float, int]]],
    connections: list[TopoConnection],
    *,
    description: str,
    skip_mtime: bool,
) -> None:
    # With our current choice of topology, connections will be a list of size 1
    assert connections

    print("Beginning initial sync...")
    t_overall = Timer().start()

    with Timer("t_req_list", log_level=1):
        buf = bytearray()
        buf.extend(ServerOperation.LIST_SIZES_SOME_MTIMES.to_bytes(8, byteorder="big"))
        write_length_prefixed(buf, marshal.dumps(dst))
        write_length_prefixed(buf, marshal.dumps(True))
        for c in connections:
            c.writer.write(buf)
            topobuf = bytearray()
            # l2_topo helps here since there's a reduction involved
            write_length_prefixed(topobuf, marshal.dumps(c.l2_topo))
            c.writer.write(topobuf)

        await asyncio.gather(*[c.writer.drain() for c in connections])

    with Timer("t_sync", log_level=1):
        ops_and_bytes = await asyncio.gather(
            *[
                _sync_initial_one(
                    src=src,
                    dst=dst,
                    local_size_mtime_modes_future=local_size_mtime_modes_future,
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
        f"to {description} ({sum(c.num_nodes() for c in connections)} nodes) "
        f"completed in {t_overall} at {time.strftime('%H:%M:%S')}\n"
    )


def process_changes(
    changes: set[tuple[watchfiles.Change, str]], ignore_cache: GitIgnoreCache
) -> dict[str, watchfiles.Change]:
    change_by_path: dict[str, watchfiles.Change] = {}
    # changes is unordered and may contain duplicates. We deduplicate, preserving added
    # and modified changes over deleted changes (since we'll find out whether the file exists
    # or not when reading it)
    for change, path in changes:
        if ignore_cache(path, is_dir=False):
            # ignore changes to gitignored files
            continue
        if path in change_by_path:
            if change in {watchfiles.Change.added, watchfiles.Change.modified}:
                change_by_path[path] = change
        else:
            change_by_path[path] = change
    return change_by_path


async def sync_watcher_changes(
    src: str,
    dst: str,
    connections: list[TopoConnection],
    change_by_path: dict[str, watchfiles.Change],
    *,
    t_overall: Timer,
    description: str,
) -> None:
    assert change_by_path
    print(f"Detected {len(change_by_path)} changes to sync...")

    with Timer("t_local_diff", log_level=1):
        delete_ops = []
        relpaths_changed = []
        for path, change in change_by_path.items():
            relpath = os.path.relpath(path, start=src)
            if change in {watchfiles.Change.added, watchfiles.Change.modified}:
                relpaths_changed.append(relpath)
            elif change == watchfiles.Change.deleted:
                delete_ops.append((FileOperation.DELETE.value, relpath))

    with Timer("t_local_ops", log_level=1):
        write_ops, n_bytes = ops_from_changed_paths(src=src, relpaths=relpaths_changed)
        # It's important to process deletes before writes to e.g. handle renames correctly
        ops = delete_ops + write_ops
        log(f"total file size: {n_bytes:_} bytes", level=1)

    await sync_ops(dst=dst, ops=ops, connections=connections)

    t_overall.end()
    print(
        f"Sync of {len(ops)} files and {n_bytes:_} bytes to "
        f"{description} ({sum(c.num_nodes() for c in connections)} nodes) "
        f"completed in {t_overall} at {time.strftime('%H:%M:%S')}\n"
    )


REMOTE_BASE = "/tmp/simple_sync"


async def bootstrap(
    remotes: list[tuple[str, int]],
    run_callback: Callable[[list[tuple[str, int]], str], Awaitable[None]],
) -> None:
    with open(__file__, "r") as f:
        code = f.read()
    core_cmd = (
        f"mkdir -p {REMOTE_BASE}; "
        f"cd {REMOTE_BASE}; "
        f"echo -n {shlex.quote(code)} > simple_sync.py; "
        "python simple_sync.py > server.log 2>&1 &"
    )
    bash_cmd = f"nohup /bin/bash --login -c {shlex.quote(core_cmd)}"
    await run_callback(remotes, bash_cmd)


async def establish_bootstrapped_connection(
    group: TopoGroup, run_callback: Callable[[list[tuple[str, int]], str], Awaitable[None]]
) -> TopoConnection:
    after_bootstrap = False
    for _ in range(5):  # arbitrary
        if after_bootstrap:
            retry_budget = 0.0
            while True:
                try:
                    c = await TopoConnection.connect(group)
                    break
                except ConnectionError as e:
                    if retry_budget >= 1:
                        re = RuntimeError(f"Failed to establish connection: {e}")
                        for note in getattr(e, "__notes__", []):
                            re.add_note(note)
                        raise re from e
                    await asyncio.sleep(0.1)
                    if isinstance(e, ConnectionRefusedError):
                        retry_budget += 0.01
                    else:
                        # Usually some error connecting to SOCKS5 proxy
                        retry_budget += 0.33
        else:
            try:
                c = await TopoConnection.connect(group)
            except ConnectionError:
                await bootstrap(group.remotes, run_callback)
                after_bootstrap = True
                continue

        buf = bytearray()
        buf.extend(ServerOperation.HEALTHCHECK.to_bytes(8, byteorder="big"))
        write_length_prefixed(buf, marshal.dumps(c.flat_topo))
        c.writer.write(buf)
        await c.writer.drain()

        try:
            prog_version = await read_length_prefixed_async(c.reader)
        except asyncio.exceptions.IncompleteReadError:
            # Maybe we changed HEALTHCHECK operation ID
            continue
        except ConnectionResetError:
            # We encounter ConnectionResetError in the port forwarding world, as we can connect to
            # the port but the server isn't running.
            if not after_bootstrap:
                # It can take a little bit of time, so loop in the else case
                await bootstrap(group.remotes, run_callback)
            after_bootstrap = True
            continue

        if not prog_version.startswith(b"simplesync"):
            raise RuntimeError(f"Unknown program running on {c.leader_str}: {prog_version!r}")

        version = prog_version.removeprefix(b"simplesync")
        if version != self_version():
            if after_bootstrap:
                if version == b"unhealthy":
                    raise RuntimeError(
                        f"At least one node failed bootstrap healthcheck. "
                        f"Check server side logs on {c.leader_str} to investigate"
                    )
                else:
                    raise RuntimeError(
                        f"Unfixable version mismatch between client and server on {c.leader_str}: "
                        f"client={self_version()!r}, server={version!r}"
                    )

            print(
                f"Detected version mismatch between client and server on {c.leader_str}, updating..."
            )

            buf = bytearray()
            buf.extend(ServerOperation.SELF_KILL.to_bytes(8, byteorder="big"))
            write_length_prefixed(buf, marshal.dumps(c.flat_topo))
            c.writer.write(buf)
            await c.writer.drain()
            c.writer.close()
            await c.writer.wait_closed()
            try:
                assert await read_length_prefixed_async(c.reader) == b"GOODBYE"
            except EOFError:
                pass

            await asyncio.sleep(0.1)  # seems needed to avoid ConnectionResetError :-/
            await bootstrap(group.remotes, run_callback)
            after_bootstrap = True
            continue

        log(f"Bootstrapped connection to {c.leader_str}", level=1)
        return c

    raise RuntimeError("Failed to bootstrap connection")


class ReliableWatch:
    def __init__(self, src: str) -> None:
        self.src = src
        self.watcher = watchfiles.awatch(src, watch_filter=None)
        # Start running the watcher early so we don't miss any changes
        self.next_change = asyncio.ensure_future(anext(self.watcher))

    async def get_changes(self) -> set[tuple[watchfiles.Change, str]] | None:
        while True:
            done, pending = await asyncio.wait([self.next_change], timeout=60)
            if done:
                assert done.pop() is self.next_change
                ret = await self.next_change
                self.next_change = asyncio.ensure_future(anext(self.watcher))
                return ret

            # Just check if the file watcher is working...
            common_paths = [".git", ".DS_Store", "README.md", "__pycache__"]
            dummy = next(
                (absp for p in common_paths if os.path.exists(absp := os.path.join(self.src, p))),
                None,
            )
            if dummy:
                os.utime(dummy, None)

                done, pending = await asyncio.wait([self.next_change], timeout=2)
                if pending:
                    raise RuntimeError("The file watcher seems to have broken. Please restart.")


async def client(
    *,
    src: str,
    dst: str,
    # See docstring of TopoGroup
    remote_groups: list[TopoGroup] | dict[str, list[tuple[str, int]]],
    # run_callback is a function that takes a list of remotes and a command to run on them
    run_callback: Callable[[list[tuple[str, int]], str], Awaitable[None]],
    description: str,
    on_local_change_event: asyncio.Event | None = None,
    skip_mtime: bool = False,
    once: bool = False,
) -> None:

    print(
        f"{'=' * 10} WARNING {'=' * 10}\n"
        "This is a very simple code upload tool with several major downsides:\n"
        "- It doesn't have a command to wait for sync to complete\n"
        "- It's not well tested\n"
        "- It doesn't do anything clever for small deltas to large files\n"
        "\n"
        "However, it's got one major upside:\n"
        "- It's fast!\n"
        f"{'=' * 29}\n"
    )

    if isinstance(remote_groups, dict):
        remote_groups = [
            TopoGroup(name, remotes, RawConnection.connect)
            for name, remotes in remote_groups.items()
        ]
    print()
    for group in remote_groups:
        print(f"Syncing {src} to {dst} on {len(group.remotes)} remote nodes in {group.name}...")
    print()

    print("Bootstrapping...")
    ignore_cache = GitIgnoreCache()
    local_size_mtime_modes_future = asyncio.get_running_loop().run_in_executor(
        None, collect_file_size_mtime_modes, src, ignore_cache
    )

    with Timer() as t_bootstrap:
        connections = await asyncio.wait_for(
            asyncio.gather(
                *[establish_bootstrapped_connection(group, run_callback) for group in remote_groups]
            ),
            timeout=CLIENT_TIMEOUT,
        )

    print(f"Bootstrapped remote daemons in {t_bootstrap}\n")

    await _client_bootstrapped(
        src=src,
        dst=dst,
        skip_mtime=skip_mtime,
        description=description,
        once=once,
        on_local_change_event=on_local_change_event,
        ignore_cache=ignore_cache,
        local_size_mtime_modes_future=local_size_mtime_modes_future,
        connections=connections,
    )


async def _client_bootstrapped(
    *,
    src: str,
    dst: str,
    skip_mtime: bool,
    description: str,
    once: bool = False,
    on_local_change_event: asyncio.Event | None,
    ignore_cache: GitIgnoreCache,
    local_size_mtime_modes_future: asyncio.Future[dict[str, tuple[int, float, int]]],
    connections: list[TopoConnection],
) -> None:
    try:
        while True:
            watcher = ReliableWatch(src)

            await sync_initial(
                src,
                dst,
                local_size_mtime_modes_future,
                connections,
                skip_mtime=skip_mtime,
                description=description,
            )
            if once:
                print("One-time sync completed, exiting...")
                return
            print(f"Watching {src} for changes...\n")

            while True:
                changes = await watcher.get_changes()
                if changes is None:
                    # File watcher is broken, kick back out to initial sync
                    break

                t_overall = Timer().start()
                change_by_path = process_changes(changes, ignore_cache)
                if not change_by_path:
                    continue
                if on_local_change_event is not None:
                    on_local_change_event.set()
                await sync_watcher_changes(
                    src,
                    dst,
                    connections,
                    change_by_path,
                    t_overall=t_overall,
                    description=description,
                )

    finally:
        for c in connections:
            await c.close()


async def client_reverse(
    src: str,
    dst: str,
    remote_group: TopoGroup,
    run_callback: Callable[[list[tuple[str, int]], str], Awaitable[None]],
    once: bool,
) -> None:
    assert len(remote_group.remotes) == 1
    connection = await establish_bootstrapped_connection(remote_group, run_callback)
    print()
    print(f"Syncing {src} to {dst} from {remote_group.name}...")
    print()

    buf = bytearray()
    buf.extend(ServerOperation.REVERSE_SYNC.to_bytes(8, byteorder="big"))
    write_length_prefixed(buf, marshal.dumps(src))
    write_length_prefixed(buf, marshal.dumps(dst))
    write_length_prefixed(buf, marshal.dumps(once))
    connection.writer.write(buf)
    await connection.writer.drain()

    server = Server()
    try:
        await server.handler(connection.reader, connection.writer)
    finally:
        await connection.close()


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
            matched = m.match(path, is_dir=is_dir)
            if matched is not None:
                return matched
        # Always ignore .git directories
        if path.parts[-1] == ".git":
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
    pattern = pattern.removeprefix("/")
    if pattern.startswith("**/"):
        # A leading "**" followed by a slash means match in all directories
        pattern = pattern[3:]
        anchored = False

    assert pattern
    n = len(pattern)

    def callback(m: re.Match[str]) -> str:
        c = m.group(0)
        if c == "/**/":
            # A slash followed by two consecutive asterisks then a slash
            # matches zero or more directories
            return "(?:/|/.+/)"  # a/**/b matches a/b
        if c == "**":
            # A leading "**" followed by a slash means match in all directories
            # A trailing "/**" matches everything inside
            if m.start() == 0 or m.end() == n:
                return ".*"
            # Other consecutive asterisks are considered regular asterisks
            return "[^/]*"
        if c == "/*":
            # Seemingly undocumented?
            return "/[^/]+"
        if c == "*":
            # An asterisk "*" matches anything except a slash
            return "[^/]*"
        if c == "?":
            # The character "?" matches any one character except "/"
            return "[^/]"
        if c.startswith("[") and c.endswith("]"):
            # The range notation, e.g. [a-zA-Z], can be used to match one of
            # the characters in a range. See fnmatch(3) and the FNM_PATHNAME flag
            stuff = c[1:-1]
            if not stuff:
                return "(?!)"  # empty range: never match
            stuff = stuff.replace("\\", "\\\\")
            if stuff == "!":
                return "."  # negated empty range: match any character
            if stuff[0] == "!":
                stuff = "^" + stuff[1:]
            elif stuff[0] in {"^", "["}:
                stuff = "\\" + stuff
            return f"[{stuff}]"
        return re.escape(c)

    regexp = re.sub(r"/\*\*/|\*\*|/\*|\*|\?|\[.*\]|.", callback, pattern)
    if not anchored:
        regexp = "(?:^|.+/)" + regexp
    if pattern.endswith("/"):
        regexp += ".*$"
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

    def match(self, path: str | _PathParts, is_dir: bool) -> bool | None:
        if isinstance(path, str):
            path = _PathParts.from_str(path)
        relpath = path.relpath_posix(self._base_path)
        if relpath is None:
            return False
        if is_dir and not relpath.endswith("/"):
            relpath += "/"
        matched = None
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
