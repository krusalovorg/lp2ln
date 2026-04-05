from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Any, Optional


def write_frame(sock, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def read_frame(sock) -> bytes:
    hdr = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", hdr)
    if length > 10 * 1024 * 1024:
        raise ValueError(f"frame too large: {length}")
    return _recv_exact(sock, length)


def _recv_exact(sock, n: int) -> bytes:
    chunks: list[bytes] = []
    got = 0
    while got < n:
        part = sock.recv(n - got)
        if not part:
            raise ConnectionError("connection closed while reading frame")
        chunks.append(part)
        got += len(part)
    return b"".join(chunks)


@dataclass
class Packet:
    signature: Optional[str] = None
    data: bytes = b""
    nodes: list[str] = field(default_factory=list)
    sender: str = ""
    receiver: str = ""
    max_hops: int = 8
    chunk_stream_id: Optional[int] = None
    chunk_index: Optional[int] = None
    total_chunks: Optional[int] = None


def encode_packet(p: Packet) -> bytes:
    d: dict[str, Any] = {
        "nodes": p.nodes,
        "sender": p.sender,
        "receiver": p.receiver,
        "max_hops": p.max_hops,
        "data": list(p.data),
    }
    if p.signature is not None:
        d["signature"] = p.signature
    if p.chunk_stream_id is not None:
        d["chunk_stream_id"] = p.chunk_stream_id
    if p.chunk_index is not None:
        d["chunk_index"] = p.chunk_index
    if p.total_chunks is not None:
        d["total_chunks"] = p.total_chunks
    return json.dumps(d, separators=(",", ":")).encode("utf-8")


def decode_packet(raw: bytes) -> Packet:
    obj = json.loads(raw.decode("utf-8"))
    data = obj.get("data", [])
    if isinstance(data, list):
        data_bytes = bytes(int(x) & 0xFF for x in data)
    else:
        data_bytes = b""
    return Packet(
        signature=obj.get("signature"),
        data=data_bytes,
        nodes=list(obj.get("nodes", [])),
        sender=str(obj.get("sender", "")),
        receiver=str(obj.get("receiver", "")),
        max_hops=int(obj.get("max_hops", 8)),
        chunk_stream_id=obj.get("chunk_stream_id"),
        chunk_index=obj.get("chunk_index"),
        total_chunks=obj.get("total_chunks"),
    )


def control_request_peers(limit: int) -> bytes:
    payload = {"type": "RequestPeers", "payload": {"limit": int(limit)}}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def control_request_descriptors(limit: int) -> bytes:
    payload = {"type": "RequestDescriptors", "payload": {"limit": int(limit)}}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def control_request_adjacency() -> bytes:
    payload = {"type": "RequestAdjacency", "payload": {}}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def try_parse_control_peers_response(data: bytes) -> Optional[list[dict[str, Any]]]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if obj.get("type") != "PeersResponse":
        return None
    pl = obj.get("payload") or {}
    desc = pl.get("descriptors")
    if not isinstance(desc, list):
        return None
    return desc


def try_parse_adjacency_response(data: bytes) -> Optional[list[str]]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if obj.get("type") != "AdjacencyResponse":
        return None
    pl = obj.get("payload") or {}
    neighbors = pl.get("neighbors")
    if not isinstance(neighbors, list):
        return None
    return [str(x) for x in neighbors]


def peek_control_type(data: bytes) -> str:
    """Короткая подсказка для логов, если тело не PeersResponse."""
    if not data:
        return "<empty>"
    try:
        obj = json.loads(data.decode("utf-8"))
        t = obj.get("type")
        if isinstance(t, str):
            return t
        return f"<json keys={list(obj.keys())[:5]}>"
    except (json.JSONDecodeError, UnicodeDecodeError):
        preview = data[:80]
        try:
            return repr(preview)[1:-1]
        except Exception:
            return "<binary>"
