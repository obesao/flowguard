"""Camada de acesso ao SQLite — criação de schema e operações usadas pelo daemon e CGI."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
-- dst_prefix guarda o prefixo monitorado da linha em ambas as direções: para
-- direction='in' é o destino do tráfego (cliente recebendo); para
-- direction='out' é a origem (cliente enviando) — sempre "o prefixo protegido
-- de interesse", nunca o IP do outro lado da conversa.
-- top_dst_ips só é preenchido para direction='in' quando dst_prefix é um
-- prefixo de fato protegido (não o /24 de fallback usado pra destinos que não
-- são clientes) — é o host /32 específico dentro do prefixo que recebeu o
-- tráfego, análogo a top_src_ips mas do lado do destino.
-- dst_port=0 significa "sem granularidade de porta": toda linha de prefixo não
-- protegido, toda linha direction='out' e, em prefixos protegidos, o agregado das
-- portas efêmeras (>=1024) — só portas well-known são gravadas individualmente
-- (ver bucket_dst_port em flowguard.py; sem isso a tabela crescia ~9GB/dia).
CREATE TABLE IF NOT EXISTS flow_aggs (
  id           INTEGER PRIMARY KEY,
  ts           INTEGER NOT NULL,
  dst_prefix   TEXT NOT NULL,
  protocol     INTEGER NOT NULL,
  dst_port     INTEGER NOT NULL,
  bps          INTEGER NOT NULL,
  pps          INTEGER NOT NULL,
  flow_count   INTEGER NOT NULL,
  avg_pkt_size INTEGER NOT NULL,
  top_src_ips  TEXT,
  src_countries TEXT,
  direction    TEXT NOT NULL DEFAULT 'in',
  top_dst_ips  TEXT
);

CREATE TABLE IF NOT EXISTS attacks (
  id           INTEGER PRIMARY KEY,
  ts_start     INTEGER NOT NULL,
  ts_end       INTEGER,
  dst_prefix   TEXT NOT NULL,
  customer     TEXT,
  attack_type  TEXT NOT NULL,
  severity     TEXT NOT NULL,
  bps_peak     INTEGER,
  pps_peak     INTEGER,
  top_sources  TEXT,
  mitigated    INTEGER DEFAULT 0,
  ai_analysis  TEXT,
  dismissed    INTEGER DEFAULT 0,
  target_host  TEXT
);

CREATE TABLE IF NOT EXISTS flowspec_rules (
  id          INTEGER PRIMARY KEY,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  attack_id   INTEGER,
  dst_prefix  TEXT,
  src_prefix  TEXT,
  protocol    TEXT,
  dst_port    TEXT,
  src_port    TEXT,
  tcp_flags   TEXT,
  pkt_len     TEXT,
  action      TEXT NOT NULL,
  active      INTEGER DEFAULT 1,
  label       TEXT,
  origin      TEXT NOT NULL DEFAULT 'flowguard'
);

CREATE TABLE IF NOT EXISTS prefix_baseline (
  dst_prefix  TEXT PRIMARY KEY,
  bps_mean    REAL NOT NULL DEFAULT 0,
  bps_var     REAL NOT NULL DEFAULT 0,
  pps_mean    REAL NOT NULL DEFAULT 0,
  pps_var     REAL NOT NULL DEFAULT 0,
  samples     INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flow_aggs_ts ON flow_aggs(ts);
CREATE INDEX IF NOT EXISTS idx_flow_aggs_prefix ON flow_aggs(dst_prefix, ts);
CREATE INDEX IF NOT EXISTS idx_attacks_ts ON attacks(ts_start);
CREATE INDEX IF NOT EXISTS idx_attacks_active ON attacks(ts_end, dismissed);
"""


def _migrate(conn: sqlite3.Connection) -> None:
    """CREATE TABLE IF NOT EXISTS não adiciona coluna a tabela já existente —
    bancos criados antes da coluna direction precisam desse ALTER explícito.
    Linhas antigas ficam como 'in' (DEFAULT), que é o comportamento anterior."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(flow_aggs)")}
    if "direction" not in cols:
        conn.execute("ALTER TABLE flow_aggs ADD COLUMN direction TEXT NOT NULL DEFAULT 'in'")
        conn.commit()
    if "top_dst_ips" not in cols:
        conn.execute("ALTER TABLE flow_aggs ADD COLUMN top_dst_ips TEXT")
        conn.commit()
    attack_cols = {row["name"] for row in conn.execute("PRAGMA table_info(attacks)")}
    if "target_host" not in attack_cols:
        conn.execute("ALTER TABLE attacks ADD COLUMN target_host TEXT")
        conn.commit()
    flowspec_cols = {row["name"] for row in conn.execute("PRAGMA table_info(flowspec_rules)")}
    if "origin" not in flowspec_cols:
        # 'origin' distingue quem pediu a regra (aba Regras unificada do portal,
        # separando FlowGuard de ClientGuard) — regras antigas não tinham essa
        # informação estruturada, só um label livre; melhor esforço: qualquer regra
        # cujo label já mencione "ClientGuard" (só o bloqueio manual via proxy
        # `_cmd_block_add` do ClientGuard gera esse texto) é reclassificada.
        conn.execute("ALTER TABLE flowspec_rules ADD COLUMN origin TEXT NOT NULL DEFAULT 'flowguard'")
        conn.execute("UPDATE flowspec_rules SET origin = 'clientguard' WHERE label LIKE '%ClientGuard%'")
        conn.commit()


def connect(db_path: str, check_same_thread: bool = True) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    conn.commit()
    _migrate(conn)
    return conn


def insert_flow_aggs_batch(conn: sqlite3.Connection, rows: list[dict]) -> None:
    """Insere todos os agregados de um ciclo em uma única transação.

    Tráfego real de backbone gera dezenas de milhares de grupos (dst_prefix,
    protocol, dst_port) por ciclo de 30s — um commit por linha bloqueia o
    event loop do daemon por segundos e derruba o socket de controle.
    """
    if not rows:
        return
    conn.executemany(
        """INSERT INTO flow_aggs
           (ts, dst_prefix, protocol, dst_port, bps, pps, flow_count, avg_pkt_size,
            top_src_ips, src_countries, direction, top_dst_ips)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (r["ts"], r["dst_prefix"], r["protocol"], r["dst_port"], r["bps"], r["pps"],
             r["flow_count"], r["avg_pkt_size"], json.dumps(r["top_src_ips"]), json.dumps(r["src_countries"]),
             r.get("direction", "in"), json.dumps(r["top_dst_ips"]) if r.get("top_dst_ips") else None)
            for r in rows
        ],
    )
    conn.commit()


def prune_old_aggs(conn: sqlite3.Connection, retention_days: int, batch_size: int = 100_000) -> int:
    """Remove agregados fora da janela de retenção, em lotes com commit intermediário.

    Um DELETE único não serve aqui: no primeiro prune após 14 dias de acúmulo ele
    apagaria dezenas/centenas de milhões de linhas numa transação só — a conexão de
    escrita fica presa por minutos (nenhum ciclo de agregação/detecção grava nesse
    meio tempo) e o WAL infla vários GB de uma vez. Em lotes, cada commit libera o
    escritor pro ciclo corrente e mantém o WAL pequeno."""
    cutoff = int(time.time()) - retention_days * 86400
    total = 0
    while True:
        cur = conn.execute(
            "DELETE FROM flow_aggs WHERE rowid IN "
            "(SELECT rowid FROM flow_aggs WHERE ts < ? LIMIT ?)",
            (cutoff, batch_size),
        )
        conn.commit()
        total += cur.rowcount
        if cur.rowcount < batch_size:
            return total


def analyze(conn: sqlite3.Connection) -> None:
    """Atualiza as estatísticas do query planner — chamado 1x/dia pelo daemon (era
    junto de cada prune horário, caro demais com flow_aggs na casa de milhões de linhas)."""
    conn.execute("ANALYZE")
    conn.commit()


def daemon_stats(conn: sqlite3.Connection, window_s: int = 30) -> dict:
    since = int(time.time()) - window_s
    row = conn.execute(
        "SELECT COALESCE(SUM(bps),0) AS bps, COALESCE(SUM(pps),0) AS pps, "
        "COALESCE(SUM(flow_count),0) AS flows FROM flow_aggs WHERE ts >= ? AND direction = 'in'",
        (since,),
    ).fetchone()
    active_attacks = conn.execute(
        "SELECT COUNT(*) AS n FROM attacks WHERE ts_end IS NULL AND dismissed = 0"
    ).fetchone()["n"]
    active_rules = conn.execute(
        "SELECT COUNT(*) AS n FROM flowspec_rules WHERE active = 1"
    ).fetchone()["n"]
    return {
        "bps": row["bps"],
        "pps": row["pps"],
        "flows": row["flows"],
        "active_attacks": active_attacks,
        "active_rules": active_rules,
    }


def stats_for_prefixes(conn: sqlite3.Connection, prefixes: list[str], window_s: int = 30) -> dict[str, dict]:
    """Tráfego agregado (bps/pps/flows) para um conjunto exato de prefixos — usado pela
    visão 'monitor' do CLI, escopada à watchlist de protected_prefixes."""
    if not prefixes:
        return {}
    since = int(time.time()) - window_s
    placeholders = ",".join("?" * len(prefixes))
    rows = conn.execute(
        f"""SELECT dst_prefix, SUM(bps) AS bps, SUM(pps) AS pps, SUM(flow_count) AS flow_count
            FROM flow_aggs WHERE ts >= ? AND direction = 'in' AND dst_prefix IN ({placeholders})
            GROUP BY dst_prefix""",
        [since, *prefixes],
    ).fetchall()
    return {r["dst_prefix"]: dict(r) for r in rows}


def top_prefixes(conn: sqlite3.Connection, window_s: int = 30, limit: int = 20) -> list[dict]:
    # INDEXED BY força o range-scan por ts (estreito: ~1 ciclo de agregação) em vez de
    # idx_flow_aggs_prefix, que evitaria o ORDER BY mas obrigaria a varrer a tabela
    # inteira (milhões de linhas acumuladas) — sem isso a consulta fica progressivamente
    # mais lenta conforme o histórico cresce, mesmo dentro da janela de retenção.
    since = int(time.time()) - window_s
    rows = conn.execute(
        """SELECT dst_prefix, SUM(bps) AS bps, SUM(pps) AS pps
           FROM flow_aggs INDEXED BY idx_flow_aggs_ts
           WHERE ts >= ? AND direction = 'in'
           GROUP BY dst_prefix ORDER BY bps DESC LIMIT ?""",
        (since, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def top_flows(conn: sqlite3.Connection, window_s: int = 30, limit: int = 20) -> list[dict]:
    since = int(time.time()) - window_s
    rows = conn.execute(
        """SELECT dst_prefix, protocol, dst_port, SUM(bps) AS bps, SUM(pps) AS pps, top_src_ips
           FROM flow_aggs INDEXED BY idx_flow_aggs_ts
           WHERE ts >= ? AND direction = 'in'
           GROUP BY dst_prefix, protocol, dst_port ORDER BY bps DESC LIMIT ?""",
        (since, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def list_attacks(conn: sqlite3.Connection, active_only: bool = True, since_s: int = 86400,
                  dst_prefix: str | None = None) -> list[dict]:
    if active_only:
        query = "SELECT * FROM attacks WHERE ts_end IS NULL AND dismissed = 0"
        params: tuple = ()
        if dst_prefix:
            query += " AND dst_prefix = ?"
            params = (dst_prefix,)
        rows = conn.execute(query + " ORDER BY ts_start DESC", params).fetchall()
    else:
        cutoff = int(time.time()) - since_s
        query = "SELECT * FROM attacks WHERE ts_start >= ?"
        params = (cutoff,)
        if dst_prefix:
            query += " AND dst_prefix = ?"
            params = (cutoff, dst_prefix)
        rows = conn.execute(query + " ORDER BY ts_start DESC", params).fetchall()
    return [dict(r) for r in rows]


def list_flowspec_rules(conn: sqlite3.Connection, active_only: bool = True) -> list[dict]:
    if active_only:
        rows = conn.execute(
            "SELECT * FROM flowspec_rules WHERE active = 1 ORDER BY created_at DESC"
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM flowspec_rules ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def insert_flowspec_rule(conn: sqlite3.Connection, rule: dict) -> int:
    cur = conn.execute(
        """INSERT INTO flowspec_rules
           (created_at, expires_at, attack_id, dst_prefix, src_prefix, protocol,
            dst_port, src_port, tcp_flags, pkt_len, action, label, origin)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (rule["created_at"], rule["expires_at"], rule.get("attack_id"), rule.get("dst_prefix"),
         rule.get("src_prefix"), rule.get("protocol"), rule.get("dst_port"), rule.get("src_port"),
         rule.get("tcp_flags"), rule.get("pkt_len"), rule["action"], rule.get("label", ""),
         rule.get("origin", "flowguard")),
    )
    conn.commit()
    return cur.lastrowid


def get_flowspec_rule(conn: sqlite3.Connection, rule_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM flowspec_rules WHERE id = ?", (rule_id,)).fetchone()
    return dict(row) if row else None


def deactivate_flowspec_rule(conn: sqlite3.Connection, rule_id: int) -> None:
    conn.execute("UPDATE flowspec_rules SET active = 0 WHERE id = ?", (rule_id,))
    conn.commit()


def deactivate_flowspec_rules_by_prefix(conn: sqlite3.Connection, prefix: str, action: str) -> None:
    conn.execute(
        "UPDATE flowspec_rules SET active = 0 WHERE dst_prefix = ? AND action = ? AND active = 1",
        (prefix, action),
    )
    conn.commit()


def list_expired_flowspec_rules(conn: sqlite3.Connection, now: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM flowspec_rules WHERE active = 1 AND expires_at <= ?", (now,)
    ).fetchall()
    return [dict(r) for r in rows]


_PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}

# janelas de zoom do gráfico histórico -> tamanho de balde que mantém a contagem de
# pontos num intervalo razoável pra desenhar (entre ~60 e ~170 pontos)
WINDOW_PRESETS = {
    "1h": (3600, 60),
    "6h": (21600, 300),
    "24h": (86400, 900),
    "7d": (604800, 3600),
}


def pick_window(name: str) -> tuple[int, int]:
    return WINDOW_PRESETS.get(name, WINDOW_PRESETS["1h"])


def protocol_timeseries(conn: sqlite3.Connection, window_s: int = 300, bucket_s: int = 30,
                         dst_prefix: str | None = None) -> list[dict]:
    """Série temporal de bps por protocolo (TCP/UDP/ICMP/OTHER), em baldes de bucket_s —
    usado pelas sparklines de tráfego do dashboard e pelo gráfico de protocolo da aba
    Gráficos. dst_prefix opcional restringe a um único prefixo monitorado; sem ele,
    soma todos os prefixos (visão agregada)."""
    since = int(time.time()) - window_s
    # com dst_prefix, a busca já é restrita a um prefixo — idx_flow_aggs_prefix (dst_prefix, ts)
    # deixa o SQLite ir direto nele em vez de varrer por ts e filtrar depois (mesmo raciocínio
    # de prefix_timeseries); medido: ~40% mais rápido numa janela de 6h num prefixo bem
    # movimentado (9.5s -> 5.6s).
    if dst_prefix:
        query = """SELECT (ts / ?) * ? AS bucket, protocol, SUM(bps) AS bps
                   FROM flow_aggs INDEXED BY idx_flow_aggs_prefix
                   WHERE dst_prefix = ? AND ts >= ? AND direction = 'in'"""
        params: tuple = (bucket_s, bucket_s, dst_prefix, since)
    else:
        query = """SELECT (ts / ?) * ? AS bucket, protocol, SUM(bps) AS bps
                   FROM flow_aggs INDEXED BY idx_flow_aggs_ts
                   WHERE ts >= ? AND direction = 'in'"""
        params = (bucket_s, bucket_s, since)
    rows = conn.execute(query + " GROUP BY bucket, protocol ORDER BY bucket", params).fetchall()
    buckets: dict[int, dict] = {}
    for r in rows:
        b = buckets.setdefault(r["bucket"], {"ts": r["bucket"], "tcp": 0, "udp": 0, "icmp": 0, "other": 0})
        b[_PROTO_NAMES.get(r["protocol"], "other")] += r["bps"]
    return [buckets[k] for k in sorted(buckets)]


def all_prefixes_timeseries(conn: sqlite3.Connection, dst_prefixes: list[str], window_s: int = 21600,
                             bucket_s: int = 300) -> list[dict]:
    """Série temporal de bps de entrada por prefixo, todos juntos num único ponto por
    balde — usado pela visão 'Todos os barramentos' do gráfico histórico, pra comparar
    picos entre prefixos sem precisar trocar o select um a um. Cada ponto tem uma chave
    por prefixo (ex: {"ts": ..., "177.86.16.0/24": 12345, ...}), consumida diretamente
    pelo mesmo motor de linha usado no gráfico individual (uma 'line' por chave).
    Restrito a dst_prefixes (a lista de monitorados) pra não misturar tráfego de
    prefixos não protegidos."""
    if not dst_prefixes:
        return []
    since = int(time.time()) - window_s
    placeholders = ",".join("?" for _ in dst_prefixes)
    rows = conn.execute(
        f"""SELECT (ts / ?) * ? AS bucket, dst_prefix, SUM(bps) AS bps
           FROM flow_aggs INDEXED BY idx_flow_aggs_prefix
           WHERE direction = 'in' AND dst_prefix IN ({placeholders}) AND ts >= ?
           GROUP BY bucket, dst_prefix ORDER BY bucket""",
        (bucket_s, bucket_s, *dst_prefixes, since),
    ).fetchall()
    buckets: dict[int, dict] = {}
    for r in rows:
        b = buckets.setdefault(r["bucket"], {"ts": r["bucket"]})
        b[r["dst_prefix"]] = r["bps"]
    return [buckets[k] for k in sorted(buckets)]


def top_hosts_for_prefix(conn: sqlite3.Connection, dst_prefix: str, window_s: int = 3600, limit: int = 15) -> list[dict]:
    """Hosts /32 individuais dentro de um prefixo protegido, ranqueados por
    presença nos top_dst_ips da janela — 'qual host está consumindo mais'
    dentro do prefixo selecionado. Mesma limitação de attack_detail: occurrences
    é frequência entre ciclos, não volume exato por host."""
    since = int(time.time()) - window_s
    rows = conn.execute(
        """SELECT bps, top_dst_ips FROM flow_aggs INDEXED BY idx_flow_aggs_prefix
           WHERE dst_prefix = ? AND direction = 'in' AND ts >= ?""",
        (dst_prefix, since),
    ).fetchall()
    # ranking ponderado por bps_da_linha/(rank+1) — mesma razão e mesmo estimador
    # de attack_detail: com portas efêmeras agregadas em dst_port=0, contagem
    # simples favoreceria quem aparece em mais ciclos, não quem concentra tráfego
    stats: dict[str, list] = {}
    for r in rows:
        for i, ip in enumerate(json.loads(r["top_dst_ips"] or "[]")):
            s = stats.setdefault(ip, [0, 0])
            s[0] += 1
            s[1] += r["bps"] / (i + 1)
    top = sorted(stats.items(), key=lambda kv: kv[1][1], reverse=True)[:limit]
    return [{"ip": ip, "occurrences": n} for ip, (n, _w) in top]


def save_ai_analysis(conn: sqlite3.Connection, attack_id: int, analysis: str) -> bool:
    cur = conn.execute("UPDATE attacks SET ai_analysis = ? WHERE id = ?", (analysis, attack_id))
    conn.commit()
    return cur.rowcount > 0


def get_attack(conn: sqlite3.Connection, attack_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM attacks WHERE id = ?", (attack_id,)).fetchone()
    return dict(row) if row else None


def dismiss_attack(conn: sqlite3.Connection, attack_id: int) -> bool:
    """Marca um ataque ainda ativo como 'dismissed' — some da lista/contagem de ativos
    (ver list_attacks/daemon_stats, que já filtram dismissed=0) sem fechar o registro
    (ts_end continua NULL: se a condição persistir, o pico bps/pps continua atualizando
    a MESMA linha em vez de reabrir/notificar de novo, já que _evaluate casa por
    ts_end IS NULL, não por dismissed). Só vale pra ataques ainda abertos — um já
    fechado não está "marcado como suspeito" na tela, é histórico."""
    cur = conn.execute(
        "UPDATE attacks SET dismissed = 1 WHERE id = ? AND ts_end IS NULL AND dismissed = 0", (attack_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def dismiss_all_active_attacks(conn: sqlite3.Connection) -> int:
    """Botão "Limpar hosts suspeitos" do portal — marca TODOS os ataques ainda ativos
    como dismissed de uma vez. Mesma ressalva de dismiss_attack: só afeta ts_end IS NULL,
    o histórico (ataques já encerrados) não é tocado."""
    cur = conn.execute("UPDATE attacks SET dismissed = 1 WHERE ts_end IS NULL AND dismissed = 0")
    conn.commit()
    return cur.rowcount


def attack_detail(conn: sqlite3.Connection, dst_prefix: str, ts_start: int, ts_end: int | None,
                   limit: int = 10, interval_s: int = 30) -> dict:
    """Detalhamento factual (sem IA) de um ataque: tráfego por protocolo/porta e IPs de
    origem observados na janela do ataque — derivado de flow_aggs, já que a coluna
    attacks.top_sources nunca é preenchida pelo detector (ele só vê totais agregados,
    não flows individuais). top_src_ips por linha já é uma amostra (top 10 por ciclo de
    agregação), então 'occurrences' é quantos ciclos aquele IP apareceu nesse top — não é
    volume exato em bytes por IP, que não é armazenado.

    Busca linhas individuais (não agregadas em SQL) porque SUM(bps) por porta precisa
    somar todos os ciclos, e top_src_ips é uma coluna não-agregada — misturar os dois
    num único GROUP BY faria o SQLite devolver o top_src_ips de um ciclo arbitrário só,
    descartando as origens dos outros ciclos da janela do ataque.

    Bytes/pacotes totais são estimados a partir de bps/pps (taxas por ciclo), não
    armazenados diretamente — daí a necessidade de interval_s (aggregate_interval_s do
    config) pra converter taxa em volume: bytes ≈ bps * interval_s / 8 por ciclo."""
    until = ts_end or int(time.time())
    rows = conn.execute(
        """SELECT protocol, dst_port, bps, pps, flow_count, top_src_ips, top_dst_ips
           FROM flow_aggs INDEXED BY idx_flow_aggs_prefix
           WHERE dst_prefix = ? AND direction = 'in' AND ts BETWEEN ? AND ?""",
        (dst_prefix, ts_start, until),
    ).fetchall()

    by_port: dict[tuple, dict] = {}
    total_bps = total_pps = total_flows = 0
    for r in rows:
        key = (r["protocol"], r["dst_port"])
        agg = by_port.setdefault(
            key, {"protocol": r["protocol"], "dst_port": r["dst_port"], "bps": 0, "pps": 0, "flow_count": 0}
        )
        agg["bps"] += r["bps"]
        agg["pps"] += r["pps"]
        agg["flow_count"] += r["flow_count"]
        total_bps += r["bps"]
        total_pps += r["pps"]
        total_flows += r["flow_count"]
    top_ports = sorted(by_port.values(), key=lambda p: p["bps"], reverse=True)[:limit]
    top_keys = {(p["protocol"], p["dst_port"]) for p in top_ports}

    for p in top_ports:
        p["total_bytes"] = p["bps"] * interval_s // 8
        p["total_packets"] = p["pps"] * interval_s
        p["avg_pkt_size"] = p["total_bytes"] // p["total_packets"] if p["total_packets"] else 0

    # só conta origens/hosts das portas/protocolos que de fato dominam o ataque
    # (top_ports) — senão tráfego legítimo do cliente em outras portas, na mesma
    # janela, dilui/esconde os IPs que efetivamente atacaram.
    #
    # O RANKING pondera cada aparição por bps_da_linha/(rank+1), não só conta ciclos:
    # com as portas efêmeras colapsadas em dst_port=0, a linha do ataque divide o
    # grupo com o tráfego legítimo do prefixo — um host movimentado que aparece em
    # toda linha da janela "ganharia" por contagem simples do host atacado, que só
    # aparece nas linhas (gigantes) do ataque. O decaimento por rank importa porque
    # top_*_ips vem ordenado por bytes e o bps é da LINHA inteira: sem ele, todo
    # host do top-10 da linha do ataque herdaria o mesmo peso do host nº 1.
    # occurrences continua sendo a contagem de ciclos, só a ordenação usa o peso.
    src_stats: dict[str, list] = {}   # ip -> [occurrences, peso]
    dst_stats: dict[str, list] = {}
    for r in rows:
        if (r["protocol"], r["dst_port"]) not in top_keys:
            continue
        for i, ip in enumerate(json.loads(r["top_src_ips"] or "[]")):
            s = src_stats.setdefault(ip, [0, 0])
            s[0] += 1
            s[1] += r["bps"] / (i + 1)
        for i, ip in enumerate(json.loads(r["top_dst_ips"] or "[]")):
            s = dst_stats.setdefault(ip, [0, 0])
            s[0] += 1
            s[1] += r["bps"] / (i + 1)
    top_sources = sorted(src_stats.items(), key=lambda kv: kv[1][1], reverse=True)[:limit]
    top_hosts = sorted(dst_stats.items(), key=lambda kv: kv[1][1], reverse=True)[:limit]
    return {
        "by_port": top_ports,
        "top_sources": [{"ip": ip, "occurrences": n} for ip, (n, _w) in top_sources],
        "top_hosts": [{"ip": ip, "occurrences": n} for ip, (n, _w) in top_hosts],
        "summary": {
            "duration_s": until - ts_start,
            "cycles": len(rows),
            "total_bytes": total_bps * interval_s // 8,
            "total_packets": total_pps * interval_s,
            "total_flows": total_flows,
        },
    }


def attack_top_host(conn: sqlite3.Connection, dst_prefix: str, ts_start: int, ts_end: int | None) -> str | None:
    """Host /32 que mais concentrou tráfego num ataque — usado pra enriquecer a
    listagem de ataques (coluna Alvo) sem duplicar a lógica de attack_detail."""
    detail = attack_detail(conn, dst_prefix, ts_start, ts_end, limit=1)
    hosts = detail["top_hosts"]
    return hosts[0]["ip"] if hosts else None


def list_open_attacks_by_key(conn: sqlite3.Connection) -> dict[tuple, dict]:
    """Todos os ataques em aberto, de uma vez — usado pela engine de detecção para
    evitar 1 SELECT por (prefixo, tipo) avaliado a cada ciclo."""
    rows = conn.execute("SELECT * FROM attacks WHERE ts_end IS NULL").fetchall()
    return {(r["dst_prefix"], r["attack_type"]): dict(r) for r in rows}


def apply_attack_changes(conn: sqlite3.Connection, to_insert: list[dict],
                          to_update: list[tuple], to_close: list[tuple]) -> list[int]:
    """Aplica todas as mudanças de um ciclo de detecção numa única transação —
    evita dezenas de commits individuais por ciclo (1 por prefixo x tipo de ataque).
    Retorna os ids inseridos, na mesma ordem de to_insert — quem chama usa isso pra
    casar cada novo ataque com sua entrada correspondente em to_notify (1:1, ver
    DetectionEngine._evaluate) sem precisar de outro SELECT."""
    inserted_ids: list[int] = []
    for item in to_insert:
        cur = conn.execute(
            """INSERT INTO attacks (ts_start, dst_prefix, customer, attack_type, severity, bps_peak, pps_peak)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (item["ts_start"], item["dst_prefix"], item["customer"], item["attack_type"],
             item["severity"], item["bps_peak"], item["pps_peak"]),
        )
        inserted_ids.append(cur.lastrowid)
    for attack_id, bps, pps in to_update:
        conn.execute(
            "UPDATE attacks SET bps_peak = MAX(bps_peak, ?), pps_peak = MAX(pps_peak, ?) WHERE id = ?",
            (bps, pps, attack_id),
        )
    for attack_id, ts_end, dst_prefix, ts_start in to_close:
        # calculado uma vez, no encerramento — evita recalcular pra cada ataque
        # fechado a cada vez que a lista é exibida (ver attack_top_host/attack_detail)
        target_host = attack_top_host(conn, dst_prefix, ts_start, ts_end)
        conn.execute(
            "UPDATE attacks SET ts_end = ?, target_host = ? WHERE id = ?", (ts_end, target_host, attack_id)
        )
    conn.commit()
    return inserted_ids


def get_baseline(conn: sqlite3.Connection, dst_prefix: str) -> dict | None:
    row = conn.execute("SELECT * FROM prefix_baseline WHERE dst_prefix = ?", (dst_prefix,)).fetchone()
    return dict(row) if row else None


def list_baselines(conn: sqlite3.Connection) -> dict[str, dict]:
    """Todas as baselines de uma vez — usado pela engine de detecção para evitar
    1 SELECT por prefixo avaliado a cada ciclo (mesmo padrão de list_open_attacks_by_key)."""
    rows = conn.execute("SELECT * FROM prefix_baseline").fetchall()
    return {r["dst_prefix"]: dict(r) for r in rows}


def update_baselines(conn: sqlite3.Connection, updates: list[tuple]) -> None:
    """Atualiza a baseline (EWMA de média/variância de bps e pps) de uma lista de
    prefixos numa única transação por ciclo.

    `updates` é uma lista de (dst_prefix, bps, pps, alpha, now). Prefixos com ataque
    ativo no ciclo (estático ou por anomalia) não devem aparecer aqui — ver
    analyzer/engine.py — senão a baseline aprende o próprio ataque como tráfego normal.
    """
    for dst_prefix, bps, pps, alpha, now in updates:
        row = conn.execute(
            "SELECT bps_mean, bps_var, pps_mean, pps_var FROM prefix_baseline WHERE dst_prefix = ?",
            (dst_prefix,),
        ).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO prefix_baseline (dst_prefix, bps_mean, bps_var, pps_mean, pps_var, samples, updated_at)
                   VALUES (?, ?, 0, ?, 0, 1, ?)""",
                (dst_prefix, bps, pps, now),
            )
            continue
        bps_mean, bps_var, pps_mean, pps_var = row
        new_bps_mean = bps_mean + alpha * (bps - bps_mean)
        new_bps_var = (1 - alpha) * (bps_var + alpha * (bps - bps_mean) ** 2)
        new_pps_mean = pps_mean + alpha * (pps - pps_mean)
        new_pps_var = (1 - alpha) * (pps_var + alpha * (pps - pps_mean) ** 2)
        conn.execute(
            """UPDATE prefix_baseline SET bps_mean = ?, bps_var = ?, pps_mean = ?, pps_var = ?,
               samples = samples + 1, updated_at = ? WHERE dst_prefix = ?""",
            (new_bps_mean, new_bps_var, new_pps_mean, new_pps_var, now, dst_prefix),
        )
    conn.commit()


def prefix_timeseries(conn: sqlite3.Connection, dst_prefix: str, window_s: int = 3600, bucket_s: int = 60) -> list[dict]:
    """Série temporal de bps/pps de um único prefixo, separada por direção
    (in = tráfego recebido, out = tráfego enviado) — usado pelo gráfico histórico
    do dashboard. Índice por (dst_prefix, ts) é o certo aqui: a busca já é restrita
    a um prefixo, então vale mais ir direto a ele do que escanear por ts."""
    since = int(time.time()) - window_s
    rows = conn.execute(
        """SELECT (ts / ?) * ? AS bucket, direction, SUM(bps) AS bps, SUM(pps) AS pps
           FROM flow_aggs INDEXED BY idx_flow_aggs_prefix
           WHERE dst_prefix = ? AND ts >= ?
           GROUP BY bucket, direction ORDER BY bucket""",
        (bucket_s, bucket_s, dst_prefix, since),
    ).fetchall()
    buckets: dict[int, dict] = {}
    for r in rows:
        b = buckets.setdefault(r["bucket"], {"ts": r["bucket"], "bps_in": 0, "pps_in": 0, "bps_out": 0, "pps_out": 0})
        b[f"bps_{r['direction']}"] = r["bps"]
        b[f"pps_{r['direction']}"] = r["pps"]
    return [buckets[k] for k in sorted(buckets)]


def attack_timeseries(conn: sqlite3.Connection, dst_prefix: str, ts_start: int, ts_end: int | None,
                       target_points: int = 90) -> list[dict]:
    """Série temporal de bps/pps de um prefixo numa janela ABSOLUTA (ts_start..ts_end) —
    diferente de prefix_timeseries, que é sempre relativa a 'agora'. Usada pra desenhar a
    linha do tempo de um ataque específico, inclusive um já encerrado há dias (dentro da
    retenção). bucket_s é escolhido pra manter a quantidade de pontos legível independente
    da duração real do ataque (segundos a horas)."""
    until = ts_end or int(time.time())
    span = max(1, until - ts_start)
    bucket_s = max(30, span // target_points)
    rows = conn.execute(
        """SELECT (ts / ?) * ? AS bucket, SUM(bps) AS bps, SUM(pps) AS pps
           FROM flow_aggs INDEXED BY idx_flow_aggs_prefix
           WHERE dst_prefix = ? AND direction = 'in' AND ts BETWEEN ? AND ?
           GROUP BY bucket ORDER BY bucket""",
        (bucket_s, bucket_s, dst_prefix, ts_start, until),
    ).fetchall()
    return [{"ts": r["bucket"], "bps": r["bps"], "pps": r["pps"]} for r in rows]
