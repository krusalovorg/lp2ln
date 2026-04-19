from __future__ import annotations

import errno
import logging
import socket
import time
from typing import Any, List, Optional, Tuple

from .wire import Packet, decode_packet, encode_packet, read_frame, write_frame

logger = logging.getLogger(__name__)

VIEWER_PEER_ID = "6c70326c6e2d746f706f6c6f67792d766965776572"


def _is_transient_socket_resource_error(err: BaseException) -> bool:
    """Windows: WSAENOBUFS 10055; также ENOBUFS/EMFILE при лавине исходящих TCP."""
    if not isinstance(err, OSError):
        return False
    win = getattr(err, "winerror", None)
    if win == 10055:  # WSAENOBUFS — «буфер слишком мал / очередь переполнена»
        return True
    no = err.errno
    if no == 10055:
        return True
    enobufs = getattr(errno, "ENOBUFS", None)
    if enobufs is not None and no == enobufs:
        return True
    if no in (errno.EMFILE, errno.ENFILE):
        return True
    return False


def connect_and_handshake(
    host: str,
    port: int,
    *,
    timeout: float = 10.0,
    our_peer_id: str = VIEWER_PEER_ID,
    resource_connect_attempts: int = 8,
    resource_backoff_s: float = 0.2,
) -> Tuple[socket.socket, str, Optional[List[dict[str, Any]]]]:
    """Первый кадр с сервера: обычно hs_ack или handshake; при перегрузке — PeersResponse (redirect)."""
    from . import wire as _wire

    attempts = max(1, int(resource_connect_attempts))
    sock: Optional[socket.socket] = None
    last_err: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        try:
            logger.info("TCP connect %s:%s (timeout=%ss)", host, port, timeout)
            sock = socket.create_connection((host, port), timeout=timeout)
            break
        except OSError as e:
            last_err = e
            if _is_transient_socket_resource_error(e) and attempt < attempts:
                delay = float(resource_backoff_s) * (2 ** (attempt - 1))
                delay = min(delay, 8.0)
                logger.warning(
                    "TCP connect %s:%s: временная нехватка ресурсов сокета (%s), пауза %.2fs (%s/%s)",
                    host,
                    port,
                    e,
                    delay,
                    attempt,
                    attempts,
                )
                time.sleep(delay)
                continue
            raise

    if sock is None:
        assert last_err is not None
        raise last_err

    try:
        sock.settimeout(timeout)

        hs = Packet(
            sender=our_peer_id,
            receiver="",
            data=b"",
            nodes=[],
            max_hops=8,
        )
        raw_hs = encode_packet(hs)
        write_frame(sock, raw_hs)
        logger.debug("handshake sent, frame %s bytes, sender=%s", len(raw_hs) + 4, our_peer_id[:16] + "...")

        remote_raw = read_frame(sock)
        remote_pkt = decode_packet(remote_raw)
        remote_id = remote_pkt.sender
        if not remote_id:
            raise RuntimeError("handshake: empty peer id from server")
        redirect = _wire.try_parse_control_peers_response(remote_pkt.data)
        if redirect is not None:
            logger.info(
                "Первый кадр — PeersResponse (%s дескр.): redirect при лимите/дубликате сессии; prefix=%s…",
                len(redirect),
                remote_id[:12],
            )
        else:
            logger.info("handshake OK, remote peer_id prefix=%s…", remote_id[:12])
        return sock, remote_id, redirect
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise


def send_control_local(
    sock: socket.socket,
    *,
    our_peer_id: str,
    remote_peer_id: str,
    control_json_bytes: bytes,
    max_hops: int = 2,
) -> None:
    p = Packet(
        sender=our_peer_id,
        receiver="",
        data=control_json_bytes,
        nodes=[],
        max_hops=max_hops,
    )
    write_frame(sock, encode_packet(p))
    logger.debug(
        "control packet sent (%s bytes data), to session peer=%s…",
        len(control_json_bytes),
        remote_peer_id[:12],
    )


def recv_packet(sock: socket.socket, *, timeout: Optional[float] = None) -> Packet:
    old = sock.gettimeout()
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        frame = read_frame(sock)
        pkt = decode_packet(frame)
        logger.debug(
            "recv frame %s bytes, sender=%s… receiver=%s… data_len=%s",
            len(frame),
            (pkt.sender or "")[:12],
            (pkt.receiver or "")[:12],
            len(pkt.data),
        )
        return pkt
    finally:
        sock.settimeout(old)
