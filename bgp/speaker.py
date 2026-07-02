#!/usr/bin/env python3
"""flowguard-speaker — processo ExaBGP do FlowGuard (configurado em exabgp.conf como
`process`). Faz a ponte entre dois canais:

  ExaBGP <-> este processo: stdin/stdout, conforme a API descrita em exabgp.conf(5)
            (comandos para o ExaBGP são sempre texto, mesmo com encoder json — esse
            encoder só formata as mensagens que o ExaBGP manda PARA este processo).
  daemon FlowGuard <-> este processo: socket Unix dedicado (bgp.exabgp_socket no
            config.yaml) — não dá pra usar o stdin do processo pra isso porque o
            ExaBGP já é quem fala com ele.
"""

from __future__ import annotations

import json
import logging
import os
import socketserver
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from bgp import flowspec

LOG = logging.getLogger("flowguard.bgp.speaker")

DEFAULT_CONFIG_PATH = "/root/flowguard/config.yaml"
_stdout_lock = threading.Lock()

# Estado dos peers BGP, populado por drain_exabgp_stdin() a partir das notificações
# "neighbor-changes" do ExaBGP (exabgp.conf precisa ter `neighbor-changes;` no bloco
# api) e consultado por get_neighbor_state()/CommandHandler — chave é o IP do peer.
_state_lock = threading.Lock()
_neighbor_state: dict[str, dict] = {}


def send_to_exabgp(command: str) -> None:
    with _stdout_lock:
        sys.stdout.write(command + "\n")
        sys.stdout.flush()


def _handle_exabgp_message(msg: dict) -> None:
    # formato das notificações "state" do encoder json do ExaBGP (up/down/connected),
    # ver exabgp/reactor/api/response/json.py — só isso nos interessa aqui.
    if msg.get("type") != "state":
        return
    neighbor = msg.get("neighbor") or {}
    peer = (neighbor.get("address") or {}).get("peer")
    state = neighbor.get("state")
    if not peer or not state:
        return
    with _state_lock:
        _neighbor_state[peer] = {
            "state": state,
            "reason": neighbor.get("reason", ""),
            "updated_at": int(time.time()),
        }
    LOG.info("estado BGP do peer %s: %s", peer, state)


def get_neighbor_state() -> dict:
    with _state_lock:
        return dict(_neighbor_state)


def drain_exabgp_stdin() -> None:
    """Consome as notificações que o ExaBGP manda a este processo (JSON, por causa de
    `encoder json` no exabgp.conf) — a maioria só é logada, mas notificações de tipo
    "state" (up/down/connected) atualizam _neighbor_state pra consulta via socket."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        LOG.debug("exabgp -> speaker: %s", line)
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        _handle_exabgp_message(msg)


class CommandHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            data = self.request.recv(65536)
            if not data:
                return
            req = json.loads(data.decode("utf-8").strip())
            if req.get("action") == "status":
                response = {"ok": True, "neighbors": get_neighbor_state()}
            else:
                command = flowspec.build_command(req["action"], req["kind"], req["rule"])
                send_to_exabgp(command)
                LOG.info("speaker -> exabgp: %s", command)
                response = {"ok": True}
        except Exception as exc:
            LOG.exception("erro ao processar comando do daemon")
            response = {"ok": False, "error": str(exc)}
        self.request.sendall((json.dumps(response) + "\n").encode("utf-8"))


class ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main() -> None:
    config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG_PATH
    cfg = yaml.safe_load(open(config_path, encoding="utf-8"))

    log_file = cfg.get("bgp", {}).get("speaker_log_file", "/var/log/flowguard-speaker.log")
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO, filename=log_file,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    sock_path = cfg["bgp"]["exabgp_socket"]
    Path(sock_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    threading.Thread(target=drain_exabgp_stdin, daemon=True).start()

    server = ThreadedUnixServer(sock_path, CommandHandler)
    os.chmod(sock_path, 0o600)
    LOG.info("flowguard-speaker pronto — socket de controle em %s", sock_path)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
