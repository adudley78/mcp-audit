"""Read a git repository's object store without running git (STORY-0153).

Running git inside a repository someone else controls is the attack TRUST-006
and TRUST-007 describe (its config can name programs git runs), so mcp-audit
never runs git on a scanned repository.  This module reads git's own files
instead: loose objects, pack files (pack version 2 or 3 with an index version
2, deltas of both kinds) and refs (``HEAD``, loose refs and ``packed-refs``).

Only what a history check needs is supported: SHA-1 object names, reading an
object by name and listing ref tips.  Alternates (``objects/info/alternates``)
are not followed, so an object that lives only in another store reads as
missing, like an object a shallow or partial clone never fetched.

Everything read is attacker-controlled, so every read is bounded:

* an object larger than :data:`MAX_OBJECT_BYTES` (after inflating or applying
  its deltas) is refused;
* inflating stops at the size the object's header declares, so a zlib bomb
  costs at most that size;
* a delta chain longer than :data:`MAX_DELTA_DEPTH` is refused, and a REF_DELTA
  that points back into its own chain cannot loop;
* :class:`ReadBudget` caps the total bytes inflated across one walk.

A malformed object raises :class:`GitObjectError`; a missing one returns
``None``.  Nothing is written and no network is used.
"""

from __future__ import annotations

import mmap
import os
import stat as stat_module
import zlib
from bisect import bisect_left
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

#: Largest object this reader will return, inflated and resolved.
MAX_OBJECT_BYTES = 32 * 1024 * 1024
#: Longest delta chain followed (git's own default is 50; ``--depth`` allows 4095).
MAX_DELTA_DEPTH = 1_000
#: Bytes of resolved objects kept for reuse as delta bases.
CACHE_BYTES = 64 * 1024 * 1024
#: Refs read (loose and packed together).
MAX_REFS = 20_000
#: Pack index files opened.
MAX_PACKS = 512
#: Bytes read from a ref, ``HEAD`` or ``packed-refs`` line file.
_MAX_REF_FILE_BYTES = 64 * 1024 * 1024
_MAX_SYMREF_HOPS = 5
#: Largest pack index read (about 20 million objects).
_MAX_INDEX_BYTES = 1024 * 1024 * 1024
_INFLATE_CHUNK = 64 * 1024

TYPE_NAMES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_OFS_DELTA = 6
_REF_DELTA = 7
_HEX = frozenset("0123456789abcdef")


class GitObjectError(Exception):
    """An object or index could not be read as git writes them."""


class BudgetExceededError(GitObjectError):
    """The walk's inflate budget ran out."""


@dataclass
class ReadBudget:
    """Total bytes one walk may inflate; shared by every read."""

    limit: int = 1024 * 1024 * 1024
    used: int = 0

    def charge(self, n: int) -> None:
        """Count *n* inflated bytes; raise when the total passes the limit."""
        self.used += n
        if self.used > self.limit:
            raise BudgetExceededError("inflate budget exhausted")


def is_object_id(text: str) -> bool:
    """True for a 40-character lower-case hex SHA-1 object name."""
    return len(text) == 40 and all(c in _HEX for c in text)


def _read_regular(path: Path, limit: int) -> bytes | None:
    """A regular file of at most *limit* bytes; ``None`` for anything else."""
    try:
        st = os.stat(path, follow_symlinks=False)
        if not stat_module.S_ISREG(st.st_mode):
            return None
        if st.st_size > limit:
            return None
        with path.open("rb") as fh:
            return fh.read(st.st_size)
    except OSError:
        return None


def inflate(data: bytes | memoryview, expected: int, budget: ReadBudget) -> bytes:
    """Inflate a zlib stream to exactly *expected* bytes.

    Stops reading input as soon as *expected* bytes are out, so a stream that
    would inflate further (a zlib bomb) costs no more than the declared size.
    """
    if expected > MAX_OBJECT_BYTES:
        raise GitObjectError(f"object of {expected} bytes is over the size cap")
    d = zlib.decompressobj()
    out = bytearray()
    view = memoryview(data)
    pos = 0
    try:
        while len(out) < expected:
            if d.unconsumed_tail:
                chunk = d.decompress(d.unconsumed_tail, expected - len(out))
            else:
                if pos >= len(view):
                    break
                piece = view[pos : pos + _INFLATE_CHUNK]
                pos += len(piece)
                chunk = d.decompress(piece, expected - len(out))
            out += chunk
            if d.eof:
                break
            if not chunk and not d.unconsumed_tail and pos >= len(view):
                break
    except zlib.error as exc:
        raise GitObjectError(f"corrupt zlib stream: {exc}") from exc
    if len(out) != expected:
        raise GitObjectError("object is shorter than its header says")
    budget.charge(expected)
    return bytes(out)


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    """A delta header size: little-endian base-128."""
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise GitObjectError("truncated delta header")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos
        if shift > 63:
            raise GitObjectError("delta size too long")


def apply_delta(base: bytes, delta: bytes) -> bytes:
    """Apply a git delta (``diff-delta.c`` format) to *base*."""
    src_size, pos = _varint(delta, 0)
    dst_size, pos = _varint(delta, pos)
    if src_size != len(base):
        raise GitObjectError("delta base has the wrong size")
    if dst_size > MAX_OBJECT_BYTES:
        raise GitObjectError(f"delta result of {dst_size} bytes is over the size cap")
    out = bytearray()
    n = len(delta)
    while pos < n:
        op = delta[pos]
        pos += 1
        if op & 0x80:
            offset = 0
            size = 0
            for i in range(4):
                if op & (1 << i):
                    if pos >= n:
                        raise GitObjectError("truncated delta copy")
                    offset |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if op & (1 << (4 + i)):
                    if pos >= n:
                        raise GitObjectError("truncated delta copy")
                    size |= delta[pos] << (8 * i)
                    pos += 1
            if size == 0:
                size = 0x10000
            if offset + size > len(base):
                raise GitObjectError("delta copies past the end of its base")
            out += base[offset : offset + size]
        elif op:
            if pos + op > n:
                raise GitObjectError("truncated delta insert")
            out += delta[pos : pos + op]
            pos += op
        else:
            raise GitObjectError("reserved delta opcode 0")
        if len(out) > dst_size:
            raise GitObjectError("delta result longer than declared")
    if len(out) != dst_size:
        raise GitObjectError("delta result shorter than declared")
    return bytes(out)


@dataclass
class _Pack:
    """One ``pack-*.idx`` / ``pack-*.pack`` pair, memory-mapped read-only."""

    idx_path: Path
    pack_path: Path
    fanout: list[int] = field(default_factory=list)
    names: list[bytes] = field(default_factory=list)
    offsets: list[int] = field(default_factory=list)
    _pack_map: mmap.mmap | None = None
    _pack_size: int = 0

    def load_index(self) -> None:
        """Read the index (version 2 only) into memory."""
        raw = _read_regular(self.idx_path, _MAX_INDEX_BYTES)
        if raw is None:
            raise GitObjectError("pack index is not a regular file")
        if len(raw) < 8 + 256 * 4 or raw[:4] != b"\xfftOc":
            raise GitObjectError("pack index is not version 2")
        if int.from_bytes(raw[4:8], "big") != 2:
            raise GitObjectError("pack index is not version 2")
        fanout = [
            int.from_bytes(raw[8 + 4 * i : 12 + 4 * i], "big") for i in range(256)
        ]
        if any(fanout[i] > fanout[i + 1] for i in range(255)):
            raise GitObjectError("pack index fanout is not sorted")
        count = fanout[255]
        names_at = 8 + 256 * 4
        crc_at = names_at + 20 * count
        off_at = crc_at + 4 * count
        big_at = off_at + 4 * count
        if len(raw) < big_at + 40:
            raise GitObjectError("pack index is truncated")
        names = [raw[names_at + 20 * i : names_at + 20 * i + 20] for i in range(count)]
        offsets: list[int] = []
        for i in range(count):
            value = int.from_bytes(raw[off_at + 4 * i : off_at + 4 * i + 4], "big")
            if value & 0x80000000:
                slot = value & 0x7FFFFFFF
                at = big_at + 8 * slot
                if at + 8 > len(raw) - 40:
                    raise GitObjectError("pack index large offset out of range")
                value = int.from_bytes(raw[at : at + 8], "big")
            offsets.append(value)
        self.fanout = fanout
        self.names = names
        self.offsets = offsets

    def find(self, oid: bytes) -> int | None:
        """Pack offset of *oid*, or ``None`` when this pack doesn't hold it."""
        first = oid[0]
        lo = self.fanout[first - 1] if first else 0
        hi = self.fanout[first]
        i = bisect_left(self.names, oid, lo, hi)
        if i < hi and self.names[i] == oid:
            return self.offsets[i]
        return None

    def data(self) -> mmap.mmap:
        """The pack file, mapped on first use."""
        if self._pack_map is None:
            try:
                st = os.stat(self.pack_path, follow_symlinks=False)
                if not stat_module.S_ISREG(st.st_mode) or st.st_size < 12:
                    raise GitObjectError("pack file is not a regular file")
                with self.pack_path.open("rb") as fh:
                    mapped = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            except OSError as exc:
                raise GitObjectError(f"pack file unreadable: {exc.strerror}") from exc
            if mapped[:4] != b"PACK" or int.from_bytes(mapped[4:8], "big") not in (
                2,
                3,
            ):
                mapped.close()
                raise GitObjectError("not a version 2 or 3 pack file")
            self._pack_map = mapped
            self._pack_size = len(mapped)
        return self._pack_map

    def close(self) -> None:
        """Unmap the pack file."""
        if self._pack_map is not None:
            self._pack_map.close()
            self._pack_map = None


class ObjectStore:
    """Read-only access to one repository's objects and refs.

    Args:
        git_dir: The repository's git directory (``.git``, or a linked
            worktree's or submodule's git dir).
        common_dir: Where ``objects/``, ``refs/`` and ``packed-refs`` live
            (*git_dir* itself unless it has a ``commondir`` file).
        budget: The walk's inflate budget.
    """

    def __init__(self, git_dir: Path, common_dir: Path, budget: ReadBudget) -> None:
        self.git_dir = git_dir
        self.common_dir = common_dir
        self.objects_dir = common_dir / "objects"
        self.budget = budget
        self.missing = 0
        self.errors: list[str] = []
        self._packs: list[_Pack] | None = None
        self._cache: OrderedDict[tuple[int, int], tuple[int, bytes]] = OrderedDict()
        self._cache_bytes = 0

    # ── Packs ────────────────────────────────────────────────────────────────

    def _load_packs(self) -> list[_Pack]:
        if self._packs is not None:
            return self._packs
        packs: list[_Pack] = []
        pack_dir = self.objects_dir / "pack"
        try:
            names = sorted(os.listdir(pack_dir))
        except OSError:
            names = []
        for name in names:
            if not (name.startswith("pack-") and name.endswith(".idx")):
                continue
            if len(packs) >= MAX_PACKS:
                self.errors.append(
                    f"more than {MAX_PACKS} pack files; the rest not read"
                )
                break
            pack = _Pack(pack_dir / name, pack_dir / (name[:-4] + ".pack"))
            try:
                pack.load_index()
            except GitObjectError as exc:
                self.errors.append(f"pack index {name} not read: {exc}")
                continue
            packs.append(pack)
        self._packs = packs
        return packs

    def close(self) -> None:
        """Release every mapped pack file."""
        for pack in self._packs or []:
            pack.close()
        self._cache.clear()
        self._cache_bytes = 0

    def __enter__(self) -> ObjectStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _remember(self, key: tuple[int, int], value: tuple[int, bytes]) -> None:
        size = len(value[1])
        if size > CACHE_BYTES // 4:
            return
        self._cache[key] = value
        self._cache_bytes += size
        while self._cache_bytes > CACHE_BYTES and self._cache:
            _key, (_t, old) = self._cache.popitem(last=False)
            self._cache_bytes -= len(old)

    def _read_packed(self, pack_no: int, offset: int, depth: int) -> tuple[int, bytes]:
        """Resolve the object at *offset* in pack *pack_no*, deltas applied."""
        pack = self._load_packs()[pack_no]
        data = pack.data()
        chain: list[tuple[tuple[int, int], bytes]] = []
        at = offset
        base: tuple[int, bytes] | None = None
        seen: set[int] = set()
        while True:
            cached = self._cache.get((pack_no, at))
            if cached is not None:
                self._cache.move_to_end((pack_no, at))
                base = cached
                break
            if at in seen or len(chain) + depth > MAX_DELTA_DEPTH:
                raise GitObjectError("delta chain too long or circular")
            seen.add(at)
            if at < 12 or at >= len(data):
                raise GitObjectError("pack offset out of range")
            pos = at
            byte = data[pos]
            pos += 1
            kind = (byte >> 4) & 7
            size = byte & 0x0F
            shift = 4
            while byte & 0x80:
                if pos >= len(data) or shift > 63:
                    raise GitObjectError("bad pack object header")
                byte = data[pos]
                pos += 1
                size |= (byte & 0x7F) << shift
                shift += 7
            if kind in TYPE_NAMES:
                base = (kind, inflate(data[pos:], size, self.budget))
                self._remember((pack_no, at), base)
                break
            if kind == _OFS_DELTA:
                if pos >= len(data):
                    raise GitObjectError("bad OFS_DELTA offset")
                byte = data[pos]
                pos += 1
                rel = byte & 0x7F
                while byte & 0x80:
                    if pos >= len(data) or rel > (1 << 56):
                        raise GitObjectError("bad OFS_DELTA offset")
                    byte = data[pos]
                    pos += 1
                    rel = ((rel + 1) << 7) | (byte & 0x7F)
                delta = inflate(data[pos:], size, self.budget)
                chain.append(((pack_no, at), delta))
                if rel <= 0 or rel > at:
                    raise GitObjectError("OFS_DELTA base out of range")
                at -= rel
                continue
            if kind == _REF_DELTA:
                if pos + 20 > len(data):
                    raise GitObjectError("truncated REF_DELTA")
                base_oid = bytes(data[pos : pos + 20])
                delta = inflate(data[pos + 20 :], size, self.budget)
                chain.append(((pack_no, at), delta))
                found = self._read_binary(base_oid, depth + len(chain))
                if found is None:
                    raise GitObjectError("REF_DELTA base is missing")
                base = found
                break
            raise GitObjectError(f"unknown pack object type {kind}")
        kind, body = base
        for key, delta in reversed(chain):
            body = apply_delta(body, delta)
            self._remember(key, (kind, body))
        return kind, body

    # ── Objects ──────────────────────────────────────────────────────────────

    def _read_loose(self, hexid: str) -> tuple[int, bytes] | None:
        path = self.objects_dir / hexid[:2] / hexid[2:]
        raw = _read_regular(path, MAX_OBJECT_BYTES * 2)
        if raw is None:
            return None
        d = zlib.decompressobj()
        try:
            head = d.decompress(raw, 64)
        except zlib.error as exc:
            raise GitObjectError(f"corrupt loose object: {exc}") from exc
        nul = head.find(b"\x00")
        if nul < 0:
            raise GitObjectError("loose object header too long")
        try:
            type_name, size_text = head[:nul].decode("ascii").split(" ")
            size = int(size_text)
        except (ValueError, UnicodeDecodeError) as exc:
            raise GitObjectError("bad loose object header") from exc
        kinds = {name: num for num, name in TYPE_NAMES.items()}
        if type_name not in kinds or size < 0:
            raise GitObjectError("bad loose object type")
        if size > MAX_OBJECT_BYTES:
            raise GitObjectError(f"object of {size} bytes is over the size cap")
        body = bytearray(head[nul + 1 :])
        try:
            while len(body) <= size and not d.eof:
                chunk = d.decompress(d.unconsumed_tail, size - len(body) + 1)
                if not chunk:
                    break
                body += chunk
        except zlib.error as exc:
            raise GitObjectError(f"corrupt loose object: {exc}") from exc
        if len(body) != size:
            raise GitObjectError("loose object size does not match its header")
        self.budget.charge(size)
        return kinds[type_name], bytes(body)

    def _read_binary(self, oid: bytes, depth: int = 0) -> tuple[int, bytes] | None:
        packs = self._load_packs()
        for number, pack in enumerate(packs):
            offset = pack.find(oid)
            if offset is not None:
                return self._read_packed(number, offset, depth)
        return self._read_loose(oid.hex())

    def read(self, hexid: str) -> tuple[str, bytes] | None:
        """``(type, body)`` for object *hexid*; ``None`` when it isn't here.

        Raises:
            GitObjectError: The object is present but malformed or too large.
            BudgetExceededError: The walk's inflate budget ran out.
        """
        if not is_object_id(hexid):
            raise GitObjectError("not a SHA-1 object name")
        found = self._read_binary(bytes.fromhex(hexid))
        if found is None:
            self.missing += 1
            return None
        return TYPE_NAMES[found[0]], found[1]

    # ── Refs ─────────────────────────────────────────────────────────────────

    def _ref_value(self, text: str, hops: int) -> str | None:
        text = text.strip()
        if is_object_id(text):
            return text
        if text.startswith("ref:") and hops < _MAX_SYMREF_HOPS:
            name = text[4:].strip()
            if not name.startswith("refs/") or ".." in name.split("/"):
                return None
            for base in (self.git_dir, self.common_dir):
                raw = _read_regular(base / name, 4096)
                if raw is not None:
                    return self._ref_value(raw.decode("ascii", "replace"), hops + 1)
            return self._packed_refs().get(name)
        return None

    def _packed_refs(self) -> dict[str, str]:
        raw = _read_regular(self.common_dir / "packed-refs", _MAX_REF_FILE_BYTES)
        refs: dict[str, str] = {}
        if raw is None:
            return refs
        for line in raw.decode("ascii", "replace").splitlines():
            if not line or line[0] in "#^":
                continue
            parts = line.split(" ", 1)
            if len(parts) == 2 and is_object_id(parts[0]):
                refs[parts[1].strip()] = parts[0]
                if len(refs) >= MAX_REFS:
                    self.errors.append(f"more than {MAX_REFS} refs; the rest not read")
                    break
        return refs

    def ref_tips(self) -> list[str]:
        """Every object a ref or ``HEAD`` points at, sorted, without repeats."""
        tips: set[str] = set(self._packed_refs().values())
        refs_dir = self.common_dir / "refs"
        count = len(tips)
        for dirpath, dirnames, filenames in os.walk(refs_dir, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                raw = _read_regular(Path(dirpath) / name, 4096)
                if raw is None:
                    continue
                value = self._ref_value(raw.decode("ascii", "replace"), 0)
                if value:
                    tips.add(value)
                count += 1
                if count >= MAX_REFS:
                    self.errors.append(f"more than {MAX_REFS} refs; the rest not read")
                    return sorted(tips)
        head = _read_regular(self.git_dir / "HEAD", 4096)
        if head is not None:
            value = self._ref_value(head.decode("ascii", "replace"), 0)
            if value:
                tips.add(value)
        return sorted(tips)


def parse_commit(body: bytes) -> tuple[str, list[str]]:
    """``(tree, parents)`` from a commit object's header."""
    tree = ""
    parents: list[str] = []
    for line in body.split(b"\n"):
        if not line:
            break
        if line.startswith(b"tree "):
            tree = line[5:].decode("ascii", "replace")
        elif line.startswith(b"parent "):
            parents.append(line[7:].decode("ascii", "replace"))
    if not is_object_id(tree) or not all(is_object_id(p) for p in parents):
        raise GitObjectError("malformed commit")
    return tree, parents


def parse_tag_target(body: bytes) -> str | None:
    """The object an annotated tag points at."""
    for line in body.split(b"\n"):
        if not line:
            break
        if line.startswith(b"object "):
            target = line[7:].decode("ascii", "replace")
            return target if is_object_id(target) else None
    return None


def tree_entries(body: bytes) -> list[tuple[bytes, bytes, str]]:
    """``(mode, name, object id)`` for each entry of a tree object."""
    entries: list[tuple[bytes, bytes, str]] = []
    pos = 0
    n = len(body)
    while pos < n:
        space = body.find(b" ", pos)
        nul = body.find(b"\x00", space + 1) if space >= 0 else -1
        if space < 0 or nul < 0 or nul + 21 > n:
            raise GitObjectError("malformed tree")
        mode = body[pos:space]
        name = body[space + 1 : nul]
        entries.append((mode, name, body[nul + 1 : nul + 21].hex()))
        pos = nul + 21
    return entries
