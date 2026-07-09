# FlowGuard

**Versão atual: v1.35.1**

Sistema de análise de tráfego BGP em tempo real e mitigação de DDoS para um
provedor de internet, modelado na arquitetura do FastNetMon. Coleta
NetFlow v9 do roteador de borda, detecta ataques por limiar
fixo e por anomalia de baseline (EWMA), e reage via BGP FlowSpec/RTBH
(ExaBGP). Expõe um socket de controle Unix consumido pela CLI
(`flowguard-cli`) e pelo [portal web](https://github.com/obesao/flowguard-portal).

## Etapas do projeto

1. **Snapshot inicial** — coletor NetFlow v9, engine de detecção (limiar fixo
   + anomalia por baseline EWMA), integração BGP/FlowSpec via ExaBGP, CLI e
   daemon.
2. **Direção in/out** — agregação e schema passaram a separar tráfego de
   entrada e saída por prefixo (necessário pros gráficos do portal).
3. **Detalhamento de ataques sem IA** — breakdown factual por protocolo/porta
   e IPs de origem, derivado de `flow_aggs`.
4. **Host `/32` individual** — rastreia qual host dentro de um prefixo
   protegido está sendo atacado/consumindo, não só o `/24`.
5. **Análise via IA** — endpoint sob demanda e relatório horário usando a API
   da Anthropic (Claude).
6. **Detalhamento enriquecido** — métricas de tráfego por porta e linha do
   tempo no painel de detalhe de ataque.
7. **Janela de tempo selecionável** no histórico de ataques.
8. **Redução de falsos positivos** no detector de anomalia de baseline.
9. **Correções operacionais** — `capacity_mbps` de prefixo corrigido,
   retenção de flows aumentada de 7 para 14 dias, falhas do ciclo de
   agregação e da análise de IA isoladas (uma não derruba a outra).
10. **Configurações via portal** (`detection_toggles.yaml`) — liga/desliga
    cada um dos 7 tipos de ataque detectados (volumétrico, 5 amplificações,
    anomalia de baseline) individualmente por checkbox, e um botão que marca
    todos os ataques ativos como dispensados de uma vez.
11. **Configuração do roteador de borda via templates** (`routercfg/`) — novo
    módulo que edita a config do roteador de borda por SSH usando templates
    validados (sem CLI livre): exportação de NetFlow, rota estática, ACL
    simples por prefixo, descrição/estado de interface. Cria um ponto de
    rollback no equipamento antes de aplicar (quando suportado) e reverte
    sozinho se o operador não confirmar a mudança dentro de alguns minutos.
    Consumido pelo portal (`flowguard-routercfg.sh`) e por
    `flowguard-cli routercfg`.
12. **Descoberta de configuração BGP real** (`routercfg/discovery.py`) — lê
    `display current-configuration configuration bgp` via SSH e extrai AS
    local, peers (IP, AS remoto, descrição, estado up/down) e prefixos
    anunciados (`network` statements). Alimenta dois templates novos: subir/
    derrubar sessão BGP com uma operadora específica (`peer ... ignore`/`undo
    ... ignore`) e anunciar/remover um prefixo da lista de IPs advertidos
    (`network`/`undo network`) — o operador escolhe peer/prefixo numa lista
    real em vez de digitar IP na mão.
13. **Visualização por operadora, interfaces e VLANs** — `discover_all()`
    unifica a leitura anterior com `display ip interface brief` e `display
    vlan brief` numa única conexão SSH; `discover_peer_routes()` lê `display
    bgp routing-table peer {ip} advertised-routes`/`received-routes` pra
    mostrar exatamente quais prefixos estão sendo anunciados/recebidos de
    cada operadora. Campos de interface em qualquer template (não só os de
    rede) agora viram uma lista real no portal em vez de texto livre. Mais 5
    templates: criar/remover VLAN, adicionar/remover VLAN de uma porta
    trunk, adicionar/remover IP de uma interface, criar/remover
    sub-interface 802.1Q.

**Pendente:** Fase 5 (IA) sem pipeline automático de eventos ainda, só
análise sob demanda.

## Estrutura

| Caminho | Papel |
|---|---|
| `flowguard.py` | Daemon principal — coleta, agregação, detecção, orquestração |
| `collector/` | Parser NetFlow v9 e matching de prefixos protegidos |
| `analyzer/engine.py` | Detecção por limiar fixo e por baseline EWMA |
| `bgp/speaker.py` | Integração BGP FlowSpec/RTBH via ExaBGP |
| `storage.py` | Schema e acesso ao SQLite |
| `socket_server.py` | Servidor de controle (Unix socket) |
| `flowguard-cli` | Cliente de terminal |
| `ai/` | Análise sob demanda via Anthropic |
| `warmode/` | "Modo Guerra" — roda comandos SSH em vários equipamentos de rede em paralelo (config em `warmode.yaml`, fora do git) |
| `routercfg/` | Edição de config do roteador de borda via templates validados (SSH, reaproveita as credenciais de `warmode.yaml`) |
| `router_templates.yaml` | Templates de configuração disponíveis (campos, validação, comandos VRP) |
| `tools/synth_netflow.py` | Gerador de NetFlow sintético para testes |
| `collector/configio.py` | Leitura/gravação de `protected_prefixes.yaml`/`whitelist.yaml`/`detection_toggles.yaml`/`mitigation_profiles.yaml` |

## Changelog

### v1.35.1 — 2026-07-09 — Corrige falso positivo do scan horizontal (CDN/big-tech flagados)

Achado real em produção, ~14h depois do deploy da v1.35.0: `port_scan_offenders`
acumulou dezenas de detecções pra IPs de Facebook/Fastly/Google (157.240.x,
151.101.x, 216.239.x) contra prefixos de clientes residenciais — falso positivo,
não scan de verdade.

Causa: o detector horizontal contava hosts distintos tocados por um src_ip
SEM exigir a mesma porta de destino — exatamente o requisito que
`clientguard/detector.py::detect_scan_horizontal` já documentava ("mesma
dst_port... sem isso, navegação normal bate o limiar"), que eu não portei pro
detector novo do FlowGuard. Um servidor de CDN respondendo a N clientes MEUS
gera N conexões, cada uma com uma porta efêmera de retorno DIFERENTE no lado
do cliente — sem agrupar por porta, isso é indistinguível de 1 atacante
varrendo N hosts na mesma porta (aparência idêntica: 1 src_ip externo, N
dst_ips distintos).

Fix: `scan_totals` agora agrupa por `(dst_port -> set(dst_ips))` em vez de um
set único; horizontal só dispara se ALGUMA porta específica tiver hosts
distintos suficientes (`analyzer/engine.py::evaluate_scan_cycle`). Como cada
cliente usa uma porta efêmera diferente pra receber a resposta, tráfego de
CDN/big-tech nunca mais bate o limiar por porta — só recon de verdade (mesma
porta varrida em vários hosts) dispara. 1 teste novo reproduzindo o cenário
exato (Facebook em 8 portas efêmeras distintas, mesmo count de hosts que
antes disparava). Nenhum bloqueio real chegou a acontecer (`auto_block`
ainda desligado desde o deploy) — só o sinal de detecção estava errado.

### v1.35.0 — 2026-07-08 — Detecção de port scan inbound + bloqueio progressivo por reincidência

Duas lacunas fechadas nesta leva: (1) `flowguard.md` documentava "Port Scan
Horizontal/Vertical" desde o spec original, nunca implementado — só existiam
detectores volumétricos (`ddos_volumetrico`, 5 amplificações, `syn_flood`,
`anomalia_baseline`); (2) bloqueio (RTBH/FlowSpec) sempre usava a mesma
duração, sem memória de reincidência — pedido do usuário: se o mesmo IP
externo repete a ofensa, o bloqueio cresce progressivamente (estilo fail2ban).

**Detector de scan inbound** (`analyzer/engine.py::evaluate_scan_cycle`, novo):
horizontal (1 src_ip externo -> N hosts distintos do prefixo, mesma porta) e
vertical (1 src_ip -> N portas distintas do mesmo host). Diferente dos
detectores existentes (chave `dst_prefix + attack_type`, pensados pra
fenômeno prefix-wide), scan é por-atacante — várias origens podem escanear o
mesmo prefixo ao mesmo tempo, cada uma rastreada/bloqueada independentemente.
Nova tabela `port_scan_offenders` (`collector/storage.py`), chave
`(dst_prefix, src_ip, scan_type)`, mesmo padrão de `attacks` (debounce,
batch write numa transação só). Acumulador `scan_totals` novo em
`flowguard.py::_aggregate_once` (mesmo bloco do `syn_totals`), usando
`rec.dst_port` CRU — não o `bucket_dst_port` já zerado pra portas
efêmeras, que é justamente onde a maioria de um scan real cai. Cap de
cardinalidade (`scan_detection.max_tracked_src_ips_per_cycle`, default 5000)
evita crescimento descontrolado sob um scan distribuído de muitas origens.
Bloqueio automático (quando ligado) chama `BgpManager.flowspec_add` direto
com `src_prefix=<atacante>/32` — não `auto_mitigate()` (que é dst_prefix-shaped,
mitigaria a vítima, não o atacante). Novo `scan_detection.yaml`
(`enabled`/`horizontal_enabled`/`vertical_enabled`/`horizontal_hosts`/
`vertical_ports`/`auto_block`/`max_tracked_src_ips_per_cycle` — limiares são
placeholders, calibrar contra tráfego real antes de confiar no sinal) +
`mitigation_profiles.port_scan_horizontal/vertical` (só `auto_mode`, kind é
sempre discard por design).

**Bloqueio progressivo** (`bgp/escalation.py`, novo): TTL do próximo
bloqueio = `base_ttl_s * factor ^ min(reincidências, max_steps)`, até o teto
`max_ttl_s`. Reincidência contada via `flowspec_rules` (nunca deleta linha,
histórico completo já existia — só faltava consultar). Novo
`escalation.yaml`. Só se aplica ao detector de scan — `ddos_volumetrico`/
amplificação/`syn_flood`/`anomalia_baseline` mitigam a vítima (RTBH/discard
no prefixo), sem um único atacante pra escalar contra.

Socket (`_cmd_scan_detection_cfg(_set)`, `_cmd_escalation_cfg(_set)`,
`_cmd_scan_offenders`), CLI (`flowguard-cli scan list|set|offenders`,
`escalation list|set`) e portal (novas seções "Detecção de Varredura de
Portas", "Bloqueio Progressivo" e "Scanners Detectados" na aba
Configuração) seguem 1:1 o padrão já existente de `detection_cfg`/
`mitigation_profiles`. 23 testes novos (`test_scan_detection.py`,
`test_bgp_escalation.py`), 412 no total, todos passando.

**Rollout recomendado**: subir com `scan_detection.auto_block: false`,
observar 24-48h calibrando `horizontal_hosts`/`vertical_ports` contra
tráfego real, só então ligar `mitigation_profiles.port_scan_*.auto_mode`.
Escalonamento pode subir junto desde o início (só afeta duração de um
bloqueio que já ia acontecer, não é risco adicional por si só).

### v1.34.0 — 2026-07-07 — Limiar de amplificação próprio + sintaxe do flowspec add + limpeza de config morto
Fecha as outras 3 pendências técnicas antigas (2026-07-02, revisão de
`flow_aggs`) escolhidas pelo usuário na mesma leva.

**Limiar de amplificação separado do volumétrico** (achado original): `amp_hit`
reusava `ddos_bps_threshold` (500M) pra decidir se dns_amp/ntp_amp/ssdp_amp/
memcached_amp/cldap_amp estava acontecendo — amplificação real tipicamente tem
volume bem menor que um DDoS volumétrico puro, então o limiar deixava passar
amplificação genuína que nunca chegava perto de 500M. Novo
`detection.amp_bps_threshold` (default 100M, 5x mais sensível), com a MESMA
cadeia de resolução que `ddos_bps_threshold` (thresholds do prefixo > template
> global — `analyzer/engine.py`), e editável por prefixo via
`monitor_add`/`monitor_set` (`api/socket_server.py`, mesmo campo `thresholds`).
4 testes novos em `tests/test_auto_mitigation.py` — achado ao escrever: a
detecção de amplificação (`AMP_PORTS`, já existente há tempos) nunca tinha
teste algum cobrindo `amp_totals` com valor real, só chamadas com `{}`.
**Não exposto ainda na UI de ajuste fino do portal** (`flowguard-portal`,
seção "Limiares de Detecção") — editável via YAML/CLI/socket, falta só o campo
no formulário do lado do `site`.

**`parse_rule_string` aceita `discard`/`rtbh` como palavra solta**: antes
exigia `discard=1`/`rtbh=1` (valor obrigatório mesmo não significando nada,
já que todo token precisava de `=`) — sintaxe estranha, nunca usada de fato em
nenhum script real do projeto. Formato antigo continua funcionando
(compatibilidade sem custo: `discard=1` ainda cai no branch de
`_RULE_STRING_ACTIONS`). 10 testes novos em `tests/test_bgp_flowspec.py` — o
parser nunca tinha teste dedicado algum.

**Config morto removido** de `config.yaml`: `collector.sflow_port`/
`ipfix_port`/`buffer_size` (o coletor só fala NetFlow v9 via UDP asyncio, sem
parser sFlow/IPFIX nem uso de buffer configurável), `threat_feeds.*` e
`geoip.*` (nenhum dos dois nunca foi implementado — confirmado grep vazio em
todo o projeto, incluindo o portal). Achado extra na mesma varredura: 5 chaves
de `detection.*` também nunca lidas por código nenhum (só listadas em
`DETECTION_TUNABLE_KEYS` de `configio.py`, sem efeito real) —
`dns_amp_factor`, `scan_ports_per_sec`, `scan_hosts_per_sec`, `window_short_s`,
`window_long_s` — removidas junto por serem exatamente a mesma classe de
problema. `FlowRecord` (`collector/models.py`) ainda tem campos de
enriquecimento nunca escritos (`src_country`/`src_category`/`is_bogon`/
`threat_score`) e `flow_aggs.src_countries` sempre grava `{}` — deixados de
fora desta limpeza (mexeriam em schema/dataclass, escopo maior que o pedido).

Suíte: 385 → 389 testes, todos passando. `flowguard.service` reiniciado em
produção duas vezes nesta sessão (reconciliação BGP + esta leva) sem erro.

### v1.33.0 — 2026-07-07 — Reconciliação BGP pós-restart do ExaBGP
Pendência conhecida desde a revisão de `flow_aggs` (2026-07-02, ver changelog
daquela versão), nunca implementada: se o `flowguard-speaker` (processo
ExaBGP) reiniciar ou a sessão TCP cair e reconectar, o ExaBGP perde toda a
RIB anunciada antes (sem graceful restart configurado) — mas `flowspec_rules`
e o portal continuavam mostrando a mitigação como "ativa", porque nada
detectava a reconexão pra re-anunciar as regras. Um restart do speaker
(deploy, OOM, o que for) apagava silenciosamente toda proteção em vigor sem
ninguém notar até o próximo ataque não ser bloqueado de verdade.

`BgpManager.check_reconciliation()` (novo, chamado a cada ciclo de agregação
— mesma cadência de `expire_cycle`, dentro de `_aggregate_once`) guarda o
último `peer_state` visto por peer (`_last_peer_state`) e detecta a transição
específica down/desconhecido → up. Na primeira checagem (cold start do
daemon) só estabelece a baseline, deliberadamente sem re-anunciar nada — o
alvo é pegar o ExaBGP reconectando ENQUANTO o daemon já está rodando, não
"toda vez que o daemon sobe" (reiniciar o daemon sozinho não afeta a sessão
BGP, que vive no processo separado do speaker). Detectada a transição,
`_reconcile_peer` relê `flowspec_rules` ativas filtradas por aquele peer
(regras de outro peer que não caiu ficam intocadas) e re-envia o mesmo
`announce` de `ban()`/`flowspec_add()` — RTBH reconstrói o comando com
`community`/`nexthop` de `config.yaml` (não persistidos na regra), FlowSpec
usa a própria linha do banco. Falha ao re-anunciar uma regra individual
loga erro e segue pras próximas, não derruba o ciclo.

10 testes novos (`tests/test_bgp_reconciliation.py`): sem re-anúncio no cold
start; re-anuncia na transição down→up; não re-anuncia com peer
permanecendo up ou down; nenhuma regra ativa não gera round-trip à toa;
com 2 peers, só as regras do peer que reconectou são re-anunciadas; RTBH
monta `community`/`nexthop` corretamente; regra expirada/desativada não é
re-anunciada; falha de envio loga e não propaga exceção. Cobertura de
`bgp/manager.py`: 87% → 89%.

### v1.32.4 — 2026-07-07 — Testes pytest pra api/socket_server.py, bgp/speaker.py e flowguard-cli.py
Fecha a leva de dívida técnica de cobertura iniciada na v1.32.2 — os 3 gaps
restantes identificados na auditoria original.

**`tests/test_socket_server_commands.py`** (61 testes): complementa
`test_socket_server.py` (que já cobria só os comandos de ajuste fino de
detecção) com os comandos "clássicos" — status/top/flows/attacks/
attack_detail/rules (resolução de nome de equipamento por peer)/ban/unban/
flowspec_add(dict e string via `parse_rule_string`)/flowspec_del/
flowspec_del_all/rule_verify/dismiss_attack(s)/toggles/mitigation_profiles/
whitelist_add-del/monitor_add-set-del-list/reload/stop/dashboard.
`FakeDaemon` grava num SQLite real (mesmo padrão de `test_wa_notifications.py`)
com um `FakeBgpManager` que só registra chamadas — o comportamento real de
BGP já é coberto por `test_bgp_manager.py`, aqui o que importa é validação de
entrada e delegação correta. `_dispatch`: comando desconhecido e exceção do
handler tratados. Cobertura de `api/socket_server.py`: 37% → 88% (resto é
`__init__`/`start`/`_handle_client`, wiring de socket/asyncio real).

**`tests/test_bgp_speaker.py`** (18 testes): parsing das notificações do
ExaBGP (`drain_exabgp_stdin`/`_handle_exabgp_message`/`get_neighbor_state`)
sem processo real — mensagem `type=state` atualiza o estado do peer, tipos
diferentes/campos ausentes são ignorados, JSON malformado no stdin não
derruba o loop, cada peer mantém estado independente. `CommandHandler.handle`
testado com um fake de socket (`recv`/`sendall`) — ação `status` retorna o
estado dos peers, `announce`/`withdraw` monta o comando FlowSpec certo e
manda pro stdout do ExaBGP (`send_to_exabgp`, capturado via `capsys`), `kind`
desconhecido e payload malformado retornam erro sem crashar. Cobertura de
`bgp/speaker.py`: 0% → 73% (resto é `main()`: config/threads/socket real).

**`tests/test_cli_helpers.py`** (48 testes): helpers puros de formatação do
`flowguard-cli.py` (importado via `importlib` por ter hífen no nome) —
`fmt_bps`/`fmt_bytes`/`fmt_duration`/`proto_name`, `resolve_socket_path`
(config ausente/sem a chave cai no default), `die_on_error` (`SystemExit`
com mensagem), `_fmt_mitigation_action`, `_fmt_rule_mechanism`/
`_fmt_rule_trigger`/`_resolve_device_name`, `_parse_set_args` (aceita `=`
dentro do valor, rejeita par sem `=`). Atenção especial a
`_fmt_activity_freshness`/`_is_genuinely_active`/`_fmt_attack_mitigation_cell`
— a lógica por trás do bug real da v1.29.0 (selo "sem proteção" aparecendo
pra ataque que já tinha parado de verdade): cobre fresco/parado/fechado/sem
`ts_last_seen`, e que o alarme só aparece quando o ataque está
GENUINAMENTE ativo. `cmd_*` (a maioria dos ~750 statements do arquivo) ficam
de fora — são principalmente `send_command` (socket real) + montagem de
tabelas `rich`, baixo valor por linha pra teste unitário e melhor validado
rodando o CLI de verdade (já é como este projeto sempre validou o CLI).
Cobertura de `flowguard-cli.py`: 0% → 18%.

Cobertura total do projeto (todos os módulos): 59% → 75%. Suíte completa:
240 → 367 testes, todos passando, sem regressão.

### v1.32.3 — 2026-07-07 — Testes pytest pra FlowGuardDaemon._aggregate_once (core da agregação)
Sequência da v1.32.2: `_aggregate_once` (flowguard.py) é o método com mais
histórico de bugs reais deste projeto (explosão de flow_aggs por porta
efêmera/cauda longa de fallback, dupla contagem ingress+egress, granularidade
de host /32, ranking de target_host) e não tinha teste nenhum.

`tests/test_aggregate_once.py` (11 testes) instancia `FlowGuardDaemon` sem
rodar `__init__` (mesmo padrão já usado em `test_wa_notifications.py`/
`test_bgp_manager.py` — seta só queue/config/conn e fakes gravando chamada
pro detector/bgp_manager), gravando num SQLite real via `tmp_path`. Cobre:
flow_direction!=0 não duplica contagem (a NE8000 exporta o mesmo pacote em
ingress+egress); `bucket_dst_port` aplicado certo (zero pra fallback mesmo
em porta well-known, mantém porta em prefixo protegido, zera porta
efêmera); `top_dst_ips` só rastreado em prefixo protegido (lista vazia vira
NULL, não `"[]"` — achado ao escrever o teste, não bug); tráfego de saída só
agregado quando o SRC é protegido; cauda longa de fallback funde no bucket
"outros" preservando os totais; `amp_totals` só some UDP em porta de
amplificação conhecida; `syn_totals` só soma SYN "puro" (exclui handshake
SYN+ACK); sampling_rate multiplica bytes/pacotes; fila vazia ainda roda
`evaluate_cycle`/`expire_cycle` (fecha ataques inativos mesmo sem tráfego
novo).

`tests/test_flowguard_helpers.py` (12 testes): `_fmt_dt`/`_fmt_duration`
(bordas: `None`/zero/negativo, singular vs plural implícito nos formatos
`XhYYmin`/`Xmin`/`Xs`) e `bucket_dst_port` isolado (fronteira exata do
`EPHEMERAL_PORT_MIN`).

Cobertura de `flowguard.py`: 30% → 50% (o resto que falta é majoritariamente
wiring de I/O — `__init__`, `setup_logging`, `udp_listener`, `daemonize`,
`main` — baixo valor por linha pra teste unitário, exercitado de fato só
rodando o daemon real). Suíte completa: 217 → 240 testes, todos passando,
sem regressão.

### v1.32.2 — 2026-07-07 — Testes pytest pra collector/prefixes.py e collector/netflow.py
Dívida técnica levantada na auditoria de cobertura (0% e 38% respectivamente,
antes desta leva) — as duas maiores lacunas em código de dado puro (sem I/O),
fácil de testar de forma isolada e crítico porque corrompe tudo rio abaixo em
silêncio se quebrar (mesma classe dos bugs reais já documentados aqui:
urldecode sob dash, exclusão de ICMP nos detectores de scan).

`tests/test_prefixes.py` (12 testes): prefixo mais específico entre entradas
sobrepostas, fallback pro prefixo mais largo, entrada malformada/sem chave
`prefix` ignorada silenciosamente, IP inválido, IPv4/IPv6, fallback pra /24
ou /64 quando não há prefixo protegido. Cobertura de `collector/prefixes.py`:
15% → 100%.

`tests/test_netflow.py` (14 testes): monta pacotes NetFlow v9 byte a byte
(RFC 3954) em vez de depender de captura real — template flowset antes/depois
do data flowset (o parser descarta em silêncio dados que chegam antes do
template correspondente, comportamento esperado do protocolo, mas nunca
testado), template com escopo por (peer, source_id, template_id), múltiplos
registros por flowset, IPv4/IPv6, campos ausentes (default 0), versão
diferente de 9, pacote truncado/mais curto que o header, `flowset_len`
apontando além do fim real do pacote (garante que o parser para em vez de
estourar), `flowset_len` abaixo do mínimo, options template (flowset_id=1)
ignorado sem erro. Cobertura de `collector/netflow.py`: 38% → 97% (as 3
linhas restantes são branches de fallback de campo raramente exercitadas,
não vale o esforço de simular). Suíte completa: 191 → 217 testes, todos
passando, sem regressão.

### v1.32.1 — 2026-07-07 — Ajuste operacional: 177.86.17.0/24 sai da auto-mitigação
`auto_mitigate`/`notify_wa` desligados e `thresholds.ddos_bps_threshold`
customizado removido (volta ao limiar global/template) pra
`177.86.17.0/24` — decisão operacional do usuário, sem mudança de código.

### v1.32.0 — 2026-07-05 — Templates e ajuste fino de detecção via portal (replica o mecanismo do ClientGuard)
Pedido do usuário: trazer pro FlowGuard o mesmo sistema de templates +
ajuste fino de limiares já construído (e validado em produção) do lado do
ClientGuard.

**Templates de detecção** (`detection_templates.yaml`, novo) — perfis
nomeados e reutilizáveis (`ddos_bps_threshold`/`ddos_pps_threshold`)
atribuíveis a qualquer prefixo via `template:` em `protected_prefixes.yaml`,
em vez de repetir o mesmo `thresholds` prefixo a prefixo. Ordem de
resolução (`analyzer/engine.py::evaluate_cycle`): `thresholds` explícito do
prefixo > `template` > limiar global de `detection.*` em `config.yaml`.

**Ajuste fino** (`detection_overrides.yaml`, novo) — sobrepõe qualquer chave
de `detection.*` sem reescrever `config.yaml` (preserva os comentários de
lá), aplicado a cada reload — que no FlowGuard já relê `config.yaml`
inteiro, dispensando qualquer estado extra em `flowguard.py` (diferente do
ClientGuard, onde o reload não relê o config principal).

Os dois editáveis via portal: nova seção "Limiares de Detecção" (17 campos,
salvamento **diff-only** — só envia ao backend as chaves realmente alteradas
pelo operador) e "Templates de Detecção" (CRUD completo), além de um
seletor de template por prefixo na tabela de monitoramento existente.

**Bug pego na validação com browser real antes do deploy**: o salvamento
diff-only comparava o valor arredondado (`Math.round`) contra o original
não-arredondado — qualquer limiar fracionário (ex: `syn_ratio_threshold:
0.9`) virava "alterado" mesmo sem o operador tocar no campo, gravando um
override espúrio (`0.9` → `1`) a cada clique em "Salvar limiares". Corrigido
antes do primeiro uso real: arredondamento agora só se aplica à conversão
Mbps→bps, nunca a limiares numéricos genéricos.

34 testes novos: 17 em `tests/test_configio.py` e 13 em
`tests/test_socket_server.py` (ambos arquivos novos), mais 4 em
`tests/test_auto_mitigation.py` cobrindo a resolução de limiar por
template na engine.

### v1.31.0 — 2026-07-05 — RTBH sempre por host /32 (achado: nunca bloqueava nada de verdade)
Pedido do usuário: auditoria de um caso real onde o portal mostrava RTBH
"aplicado" pro ataque em `x.x.x.0/24` mas o host específico continuava
respondendo ping normalmente.

**Causa raiz** (confirmada via SSH, comandos só leitura no roteador de borda):
`ban()` sempre anunciou o **prefixo inteiro do cliente** (ex: `/24`) via RTBH.
O roteador tem uma política de importação que só aceita RTBH como host `/32`
— `ip-prefix-list` com `ge 32 le 32`, desenho claramente herdado de um
FastNetMon anterior (que sempre isola o host atacado, nunca o bloco do
cliente inteiro). Qualquer anúncio mais largo cai no `deny` final da política
— **rejeitado silenciosamente**: BGP mostrava sessão `Established`/`Up`, o
FlowGuard mandava a rota certinha (community configurada, next-hop do
blackhole), mas `Received total routes: 0` no peer confirmava que nada nunca
foi de fato aceito. Ou seja, **todo RTBH que o
FlowGuard já tentou aplicar (botão manual "Mitigar" e auto-mitigação de
`ddos_volumetrico`) nunca protegeu nada de verdade** — só existia no banco
local e no log, nunca na borda real.

**Correção**: `BgpManager.ban()` agora sempre resolve pro host `/32` mais
atacado antes de montar o anúncio — usa `attacks.target_host` se já
calculado, senão recalcula ao vivo via `flow_aggs` (mesmo mecanismo dos
alertas de WhatsApp da v1.30.0); sem ataque associado (bloqueio manual avulso
de um prefixo), cai pro host mais ativo recentemente ali. Sem host
identificável (sem tráfego recente), falha com erro claro em vez de aceitar
silenciosamente um anúncio que o roteador ia descartar de qualquer jeito.
`unban()` acompanhou: quem chama continua passando o prefixo do cliente (é o
que o botão "Liberar" do portal manda), mas agora busca por regras ativas
**dentro** desse prefixo em vez de exigir igualdade exata — sem isso, liberar
pelo prefixo do cliente não acharia mais a regra (que passou a ser o host
`/32`, não o `/24`).

Efeito colateral positivo: RTBH agora blackholeia só o host atacado, não o
cliente inteiro — menos dano colateral que a v1.31.0 corrige de graça junto
com o bug.

8 testes novos (`tests/test_auto_mitigation.py`) cobrindo: resolução via
`target_host` já persistido, cálculo ao vivo quando ainda não persistido,
fallback sem ataque associado, falha clara sem host identificável, target
`/32` explícito não sofre resolução, e `unban()` encontrando/revertendo a
regra pelo prefixo do cliente.

### v1.30.1 — 2026-07-05 — Corrige "Host/prefixo: None" em regra sem dst_prefix
Achado logo depois do deploy da v1.30.0, já em produção: regras de bloqueio
automático de cliente abusivo (ClientGuard, mesmo `BgpManager`) identificam o
alvo só por `src_prefix` (ex: regra real #275, `ClientGuard auto:
port_scan_horizontal`, `src_prefix=100.64.109.236/32`, sem `dst_prefix`) — o
alerta novo de mitigação aplicada mandava literalmente "Host/prefixo: None"
pro WhatsApp nesse caso.

`flowspec_add`/`flowspec_del`/`expire_cycle` (`bgp/manager.py`) agora caem
pra `src_prefix` quando `dst_prefix` está ausente antes de repassar pro
alerta; `notify_mitigation_applied`/`notify_mitigation_reverted`
(`flowguard.py`) ganharam um último fallback pra `"?"` como rede de segurança
(nunca mais mostra `None` literal, mesmo se um chamador futuro esquecer de
passar algum prefixo). 2 testes de regressão novos.

### v1.30.0 — 2026-07-05 — Alerta de WhatsApp mostra o host exato, horários e a ação de mitigação
Pedido do usuário: o alerta de ataque só mostrava o prefixo/bloco inteiro
(ex: `x.x.x.0/24`), nunca o host `/32` de fato sendo atacado, e não dizia
nada sobre a ação de segurança tomada (RTBH/blackhole, FlowSpec) nem quando
ela começou/terminou.

**Mensagens de ataque enriquecidas** (`notify_attack`/`notify_attack_closed`
em `flowguard.py`):
- **Host exato** — abertura calcula o host `/32` mais atacado NO MOMENTO via
  `storage.attack_top_host` (mesma função já usada pro fechamento, só que
  aplicada à janela do próprio ciclo que disparou o ataque); fechamento usa o
  `attacks.target_host` já persistido. Sem host identificado (prefixo sem
  granularidade `/32`, ex: `/24` de fallback), cai pro prefixo com um aviso
  explícito em vez de fingir precisão que não existe.
- **Horários** — abertura mostra "Início: dd/mm HH:MM"; fechamento mostra
  início, fim e duração formatada (`1h02min`, etc).

**Novo par de alertas — mitigação aplicada/revertida** (`notify_mitigation_applied`/
`notify_mitigation_reverted`, disparados de dentro de `bgp/manager.py`:
`ban`/`flowspec_add` no apply, `unban`/`flowspec_del`/`expire_cycle` na
reversão): mensagens PRÓPRIAS e imediatas no momento em que a ação de
segurança de fato acontece, decoplado do ciclo de vida do ataque — RTBH TTL
padrão é 1h, mas pode ficar ativo bem depois do ataque já ter fechado, e uma
mitigação manual pode ser aplicada minutos depois da abertura. Mostram: host
exato (recalculado ao vivo se o ataque ainda não fechou e `target_host` ainda
não foi persistido), ação tomada com rótulo amigável ("Blackhole (RTBH) —
descarte total do prefixo na borda", "Descarte seletivo (FlowSpec)",
"Limitação de taxa (FlowSpec)"), se foi automática ou manual, e — na
reversão — o motivo ("TTL expirado" vs "revertida manualmente") e a duração
total da mitigação. Cobre tanto ações automáticas quanto manuais do
operador (portal/CLI) — é uma ação real na borda, vale saber sempre,
independente de quem disparou. Respeita o mesmo filtro `min_severity_wa` já
usado pros alertas de ataque (baseado na severidade do ataque associado);
sem ataque associado (bloqueio manual avulso de um IP) sempre notifica, já
que é uma ação deliberada do operador. Deliberadamente NÃO dispara em
`withdraw_all` (shutdown do daemon / botão "Apagar todas as regras") — viraria
spam a cada deploy.

17 testes novos (`tests/test_wa_notifications.py`) cobrindo conteúdo das 4
mensagens, fallback sem host identificado, filtro de severidade, e a
integração ponta a ponta com `BgpManager` (ban/unban/flowspec_add/flowspec_del/
expire_cycle disparando o alerta certo com os argumentos certos).

### v1.29.0 — 2026-07-05 — "sem proteção" não aparece mais pra ataque que já parou de verdade
Pedido do usuário: mesmo com o indicador de atividade da v1.28.0, o selo de
mitigação continuava mostrando "⚠ sem proteção" pra ataques que já não
tinham tráfego real há um tempo (🟡 sem atividade) — na prática já
encerrados, só aguardando o fechamento automático (rede de segurança de 6h).

`_fmt_attack_mitigation_cell` agora só mostra "⚠ sem proteção" quando o
ataque está GENUINAMENTE em andamento (nova `_is_genuinely_active`: mesmo
critério do 🟢/🟡 — `ts_end` nulo E `ts_last_seen` reconfirmado há menos de
90s). Se está aberto mas sem atividade recente, volta a mostrar "encerrada"
(neutro) — o alarme é "ainda te atacando sem bloqueio", não "já te atacou
uma vez sem bloqueio".

**Auditoria à parte, sobre por que alguns ataques mostram "sem mitigação"**
(nenhuma regra jamais tentada, nem manual nem automática): confirmado nos
dados reais que são 2 causas legítimas, não bug:
1. `syn_flood` (tipo novo) ainda não tem entrada em `mitigation_profiles.yaml`
   — sem perfil, `auto_mode` cai no padrão `off`, decisão já documentada no
   changelog do próprio recurso (v1.27.0).
2. Ataques antigos (ex: #88/#89, `ddos_volumetrico` em dois prefixos
   monitorados, 2026-07-04 11:36) aconteceram ANTES de
   `protected_prefixes.yaml` ser editado (mtime 12:01, mesmo dia) habilitando
   `auto_mitigate: true` pra esses prefixos — histórico legítimo, não reflete
   a config atual.

Validado com Playwright real: 0 linhas "sem atividade" mostrando "sem
proteção" nas duas telas (portal), lógica testada em isolamento pros 4 casos
de borda (aberto+fresco, aberto+parado, fechado, sem ts_last_seen).

### v1.28.0 — 2026-07-04 — Indicador "atividade recente" no CLI (attacks/attack detail)
Pedido do usuário: "ativo" sozinho não diz se o ataque está REALMENTE
acontecendo agora — na prática, na maioria das vezes o registro segue
marcado como ativo mesmo já sem tráfego real há um tempo (aguardando o
fechamento automático por inatividade, que só age depois de horas — ver
v1.26.0). Faltava uma forma rápida de diferenciar isso a olho.

`flowguard-cli attacks`/`attacks --id` ganham a coluna/linha "Atividade",
calculada a partir de `ts_last_seen` (já existente desde v1.26.0): 🟢 "em
andamento" quando a última reconfirmação foi há menos de 90s (~3 ciclos de
agregação de 30s, com folga), senão 🟡 "sem atividade há Xm/Xh". Só exibido
pra ataques ainda ativos (`ts_end` nulo) — histórico mostra "-".

Puramente de exibição no CLI, nenhuma mudança de schema/backend (o dado já
existia). Contraparte no portal (mesmo cálculo) e no ClientGuard entram em
commits próprios.

### v1.27.0 — 2026-07-04 — SYN flood: novo tipo de ataque dedicado
Pedido do usuário: pesquisar como o FastNetMon detecta DDoS e trazer
melhorias pro FlowGuard (skill nova, `.claude/skills/detection-benchmark/`,
documenta a pesquisa + o gap analysis pra reuso futuro). Achado principal:
o FlowGuard já é mais avançado em baseline (EWMA ao vivo vs. o cálculo
offline único do FastNetMon), mas não tinha SYN flood como tipo de ataque
dedicado — caía dentro do volumétrico genérico, sem diagnóstico nem
mitigação cirúrgica próprios.

**Fase 0 (diagnóstico, feito antes de decidir escopo):** fragmentação IP
também é um gap, mas SSH read-only no NE8000BGP (`display
current-configuration | include netstream`, autorizado explicitamente)
confirmou que o NetStream exportado hoje não inclui campos de fragmentação
— fica documentado como pendência, não implementado neste ciclo (mudança
de config de roteador é fora do escopo de código).

**SYN flood (`attack_type=syn_flood`):** detecção por proporção de SYN
"puro" (flag SYN setada, ACK não setada — isola o flood de SYN-ACK de
handshake real) sobre o TCP total do prefixo, só avaliada acima de um piso
de pps (`syn_min_pps_floor`, novo) pra não disparar num prefixo quase sem
tráfego. `syn_ratio_threshold` já existia em `config.yaml` desde sempre,
mas nunca era lido por nenhum código — só religado, não inventado.
`tcp_flags` já era decodificado pelo parser NetFlow (`collector/netflow.py`)
e simplesmente descartado na agregação; `flowguard.py::_aggregate_once`
ganhou `syn_totals` (mesmo padrão de `amp_totals`). Suprime a anomalia de
baseline no mesmo ciclo (evita alerta duplicado do mesmo tráfego). Severity
`high`. Registrado nos 4 lugares onde tipo de ataque precisa existir hoje
(`DEFAULT_FEATURE_TOGGLES`, `DEFAULT_MITIGATION_PROFILES`,
`detection_toggles.yaml`, `_MATCH_TEMPLATES`/`_ATTACK_LABELS` do FlowSpec) —
não existe um registry único, decisão deliberada de não refatorar isso
agora, fora do escopo pedido. **`auto_mode` nasce `off`** — diferente dos
outros 6 tipos, que o usuário já tinha configurado como `suggestion` em
produção; um detector novo e ainda não validado em produção não devia
herdar auto-mitigação silenciosamente.

**Bug real encontrado e corrigido no processo:** `bgp/flowspec.py::_describe_match`
indexava `match['src_port']` sem checar presença — quebraria com
`AttributeError`/`KeyError` pra qualquer `attack_type` sem porta de origem
fixa (como o `syn_flood` novo, que usa `tcp_flags` em vez de `src_port`).
Não havia teste nenhum cobrindo `suggest_mitigation`/`_describe_match`
antes disso — 2 testes novos em `test_bgp_flowspec.py`, incluindo um smoke
test genérico sobre todo `attack_type` conhecido, pra pegar essa mesma
classe de bug em qualquer tipo futuro.

**Nota operacional encontrada (não é bug desta versão):** a análise por IA
está falhando em produção por falta de crédito na conta Anthropic
(`credit balance is too low`) — não derruba a detecção (design já previa
isso), só perde o texto explicativo dos ataques até o crédito ser
reposto.

6 testes novos em `tests/test_auto_mitigation.py` (ratio+piso disparando,
piso sozinho não disparando, ratio sozinho não disparando, toggle
desligado suprimindo, compatibilidade retroativa de `evaluate_cycle` sem o
4º argumento) + 2 em `test_bgp_flowspec.py` — 131 testes no total, suíte
completa passando.

Validado ponta a ponta em produção com tráfego sintético real
(`tools/synth_netflow.py syn_flood`, já existia, nunca tinha sido usado
pra essa finalidade): WhatsApp temporariamente desligado antes do teste
(mesmo procedimento já usado em versões anteriores pra não alarmar o
grupo real), 4 rajadas espaçadas 12s pra sustentar acima de
`min_attack_duration_s` por 2+ ciclos consecutivos (achado no processo:
rajadas espaçadas ~80-100s caem em ciclos não-consecutivos e resetam o
timer de duração mínima — só rajadas mais próximas, ~12s, garantem
continuidade), ataque abriu como `syn_flood`/`high`/sem mitigação
automática, e fechou sozinho quando o tráfego parou — ciclo completo
abrir→sustentar→fechar confirmado. WhatsApp religado e serviço reiniciado
limpo depois. Portal (aba Configuração) confirmado mostrando o toggle e a
linha de mitigação com "Desligado" no automático (diferente de todo o
resto, de propósito).

### v1.26.0 — 2026-07-04 — Ataque não fica "ativo" pra sempre quando a mitigação expira
Pedido do usuário: um ataque na aba Ataques (portal e CLI) continuava marcado
como ativo mesmo depois que o tempo/TTL da mitigação já tinha passado.

Investigação encontrou a causa raiz real: o fechamento automático de ataques
(`DetectionEngine._evaluate`, baseado no tráfego medido cair abaixo do limiar)
já funcionava — o NetFlow é contado na entrada da interface do roteador, antes
do RTBH/FlowSpec decidir descartar, então enquanto o atacante mandar tráfego o
ataque segue "ativo" mesmo com a mitigação bloqueando de verdade. Isso é
factualmente correto (o atacante não parou), mas não havia nenhum sinal
diferenciando "ativo e protegido" de "ativo e sem proteção" (mitigação
expirada/revertida) — que é exatamente o incômodo relatado.

Duas mudanças, sem alterar a arquitetura de detecção:
- **Rede de segurança**: `attacks` ganha `ts_last_seen`, atualizado a cada
  ciclo em que o ataque continua confirmado; um novo `close_stale_attacks`
  (rodando 1x/hora, junto do prune de retenção) fecha sozinho qualquer ataque
  sem reconfirmação há mais de `detection.attack_stale_close_s` (padrão 6h) —
  cobre o caso raro em que a engine para de reavaliar a chave (prefixo
  removido de `protected_prefixes`, reload/restart no meio do ataque) e a
  linha ficaria "ativa" pra sempre.
- **Selo de mitigação mais claro**: quando o ataque continua ativo mas a
  última mitigação já não está mais em vigor, o selo muda de "encerrada"
  (neutro) para "⚠ sem proteção" (vermelho), tanto no portal quanto no CLI
  (`flowguard-cli attacks`/`attacks --id`).

Validado ao vivo: reiniciar o daemon (necessário pra carregar o código —
`withdraw_all()` no shutdown derruba as regras BGP ativas) e observar a
reconciliação automática do ClientGuard corrigir as mitigações órfãs; o selo
"⚠ sem proteção" apareceu corretamente nos sinais afetados, sem erro de
console. 5 testes novos (`tests/test_attack_lifecycle.py`) cobrindo
`ts_last_seen`/`close_stale_attacks`.

### v1.25.0 — 2026-07-04 — trigger_type + equipamento em flowspec_rules (base pra etiquetas da aba Regras)
Pedido do usuário: na aba Regras, sinalizar em cada regra FlowSpec/RTBH como
foi feito (mecanismo/equipamento), se foi automático ou manual, e se ainda
está em vigor — mesmo padrão já usado na aba Sinais Suspeitos do ClientGuard.
**Achado real ao investigar**: `flowspec_rules` nunca teve como distinguir
"disparada pelo botão Mitigar/Aplicar Sugestão" de "disparada pela engine de
auto-mitigação" — os dois caminhos gravavam a mesma estrutura, com `origin`
sempre `"flowguard"` nos dois casos (só distingue FlowGuard de ClientGuard,
não manual de automático).

- Nova coluna `trigger_type` ('manual' | 'auto') em `flowspec_rules`, migração
  no mesmo padrão de `origin`/`peer`. `BgpManager.ban()`/`flowspec_add()`
  ganham parâmetro `trigger_type` (default `'manual'`); `auto_mitigate()`
  passa `'auto'` nos dois métodos. `_cmd_ban`/`_cmd_flowspec_add` (socket)
  repassam o valor do request — usado pelo ClientGuard pra marcar suas
  próprias mitigações automáticas corretamente (ver v1.22.0 do ClientGuard).
  Regras antigas (antes desta versão) ficam `'manual'` por padrão — não dá
  pra saber com certeza retroativamente, não é um "errado conhecido".
- `_cmd_rules` (socket) e o CGI `flowguard-rules.sh` do portal (que lê o
  SQLite direto, sem passar pelo socket) resolvem `device_name` a partir do
  `peer` de cada regra — mesma lógica já usada só por `verify_rule`
  (`BgpManager._device_for_peer`), agora também na listagem normal.
- `flowguard-cli rules`/`rules --history` ganharam colunas Mecanismo,
  Equipamento e Gatilho.

9 testes novos (119 no total). Validado em produção real: uma regra
automática do próprio FlowGuard (`auto_mode: suggestion`, habilitado pelo
usuário) e outra do ClientGuard via proxy FlowSpec, ambas gravando
`trigger_type='auto'` e `device_name` corretos (o roteador de borda principal
pro peer `main`, o peer PPPoE/CGNAT pro `pppoe`) — confirmado direto no
socket, não só em teste.

### v1.24.0 — 2026-07-04 — Selo de mitigação na aba Ataques (mesmo padrão do ClientGuard)
Pedido do usuário: aplicar no FlowGuard o mesmo selo de mitigação já feito no
ClientGuard (v1.22.0) — sinalizar se um ataque já tem regra de mitigação
associada e se ela está em vigor agora. Nova `storage.
get_latest_flowspec_rule_for_attack(conn, attack_id)`: última regra (RTBH ou
FlowSpec) desse ataque, independente de `active`, pra distinguir "nunca
mitigado" de "já foi mitigado, mas a regra não está mais em vigor" (TTL
vencido, remoção manual, ou — achado real desta mesma sessão — o
`flowguard.service` reiniciar, que retira TODAS as regras ativas no shutdown
gracioso via `BgpManager.withdraw_all`). Diferente do ClientGuard, o FlowGuard
não persiste um estado "failed": `ban()`/`flowspec_add()` só gravam uma linha
quando o anúncio BGP dá certo, então só existem os estados "ativa" e
"encerrada" aqui.

`_cmd_attacks`/`_cmd_attack_detail` (socket) e o CGI `flowguard-attacks.sh`
(GET lista e `?detail=`) enriquecem cada ataque com `mitigation`.
`flowguard-cli attacks`/`attacks <id>` ganharam a mesma coluna/linha. A antiga
coluna "Mitigado" (sim/não, baseada no campo `mitigated` que só registrava
"foi mitigado alguma vez") foi substituída por esse selo mais rico.

4 testes novos (114 no total). Validado contra o daemon real: CLI mostrando
"encerrada (RTBH)" corretamente pra um ataque cuja regra RTBH foi retirada
(confirmado via consulta direta ao socket), e "🛡 ativa" pra ataques com
mitigação automática em vigor (o próprio `auto_mode: suggestion`, habilitado
pelo usuário em produção durante esta sessão, gerou casos reais pra validar).

**Achado de auditoria nesta mesma sessão** (não é bug desta versão, mas vale
registrar): reiniciar o `flowguard.service` pra testar esta feature retirou
de novo todas as regras ativas — confirmando ao vivo, pela segunda vez nesta
sessão, que a reconciliação automática do ClientGuard (v1.21.0) reage
corretamente a esse cenário. Sob a carga gerada (rajada de reconciliação +
redisparo), threads chegaram a ficar temporariamente na fila do lock global
de SSH do PBR bypass (confirmado com py-spy, não é impasse — apenas fila
grande drenando) e, num caso, um `systemctl restart` do ClientGuard no meio
de um `insert` pendente deixou 2 regras órfãs (ativas no FlowGuard, sem
registro local correspondente) — baixa severidade, autolimitado (expiram
pelo TTL), não é um problema recorrente do mecanismo em si.

### v1.23.0 — 2026-07-04 — Modo Guerra: ativar/desativar equipamento, testar conexão, histórico de execução
Pedido do usuário: melhorias na configuração do Modo Guerra — opção de
ativar/desativar um equipamento cadastrado (participar ou não do próximo
lote), e melhor visibilidade da lista. `warmode.yaml` ganha `enabled` por
equipamento (default `true`, retrocompatível). `_run_war_mode` filtra
`enabled=false` antes de montar o lote — o equipamento desativado nem entra
em `results`/audit log/WhatsApp daquela execução, mas continua salvo
(credenciais/comandos preservados) pra reativar depois sem recadastrar nada.
`list_devices()` (usado pelo modal de confirmação do portal) passou a expor
`enabled`, pro portal mostrar o equipamento desativado esmaecido com "não vai
rodar" em vez de simplesmente sumir da lista.

Duas funções novas: `test_device()` — abre/fecha uma sessão SSH sem enviar
nenhum comando de produção, só pra validar credencial/alcance antes de
precisar de verdade num incidente (reaproveita a mesma lógica de conexão de
`_run_device`, extraída pra `_connect_device()`); e `last_runs_by_device()` —
lê o audit log (`/var/log/flowguard-warmode-audit.jsonl`, existia desde a
v1.9.0 mas nunca era lido de volta) e retorna a última execução de cada
equipamento (ok/falha, quando, erro), anexada automaticamente em
`load_devices_masked()` pra aparecer na tela de configuração sem precisar
abrir log manualmente.

Validado sem tocar em nenhum equipamento real: `test_device()` chamado
diretamente contra um host inexistente (`10.255.255.254`) confirma o timeout
de 12s e a mensagem de erro esperada; lista de equipamentos/enabled/last_run
testada carregando o `warmode.yaml` real de produção (só leitura). Ver
changelog do `flowguard-portal` (v1.29.0) pro lado da UI (card colapsável,
toggle, badge de última execução, botão Testar/Duplicar/Remover com
confirmação).

### v1.22.0 — 2026-07-04 — Duração personalizável do RTBH (auto-expira sozinho)
- Pedido do usuário: poder escolher por quanto tempo um bloqueio RTBH fica no
  ar antes de ser retirado sozinho ("ex: jogar pra blackhole por 10 minutos
  depois retirar"), de forma configurável — não fixo no código. O mecanismo de
  expiração automática (`BgpManager.expire_cycle`) já existia pra toda regra
  FlowSpec/RTBH; o que faltava era conseguir personalizar essa duração
  especificamente pro RTBH.
- `mitigation_profiles.yaml` ganha uma chave global (não por tipo de ataque,
  ver `configio.RTBH_TTL_KEY`) `rtbh_default_ttl_s` (padrão: 3600s/1h, mesmo
  valor de antes — comportamento não muda pra quem não configurar nada).
  `BgpManager.ban()` passa a usar esse valor como padrão em vez do antigo
  `mitigation.default_ttl_s` do `config.yaml` (que continua valendo só pras
  regras FlowSpec de discard/rate_limit, sem mudança). A mitigação automática
  (v1.20.0, `auto_mode=rtbh` ou `suggestion` quando o kind é rtbh) também usa
  esse mesmo padrão, por consistência com o botão manual.
- `flowguard-cli mitigation rtbh-ttl [minutos]` mostra (sem argumento) ou
  define o padrão. `flowguard-cli ban <alvo> --ttl-minutes N` e o botão
  "Mitigar" da aba Ataques (novo campo de minutos ao lado do botão, no menu
  "Ações") permitem sobrescrever pontualmente só daquela vez, sem mudar o
  padrão configurado.
- 6 testes novos (roundtrip/validação do `rtbh_default_ttl_s`, `ban()` usando
  o padrão configurado vs. um override pontual), 110 no total.
- Validado ponta a ponta: CLI (`mitigation rtbh-ttl`, `ban --ttl-minutes`)
  contra o daemon real, TTL da regra resultante conferido em `flowguard-cli
  rules` (bateu com o valor pedido, não com o antigo default de 1h); portal
  validado com Playwright real (campo na aba Configuração > Mitigação,
  salvar/resetar, e o campo de minutos dentro do menu "Ações" da aba Ataques
  sem fechar o menu ao digitar — bug real que teria existido sem o ajuste em
  `initActionMenus`), 0 erros de console.

### v1.21.0 — 2026-07-04 — Modo Guerra: botão único (liga/desliga) + aviso periódico por WhatsApp com IA
Pedido do usuário: unificar os botões de ligar/desligar o Modo Guerra num só
(toggle) e, enquanto ativo, mandar atualizações periódicas pro WhatsApp com o
tempo decorrido e um resumo gerado por IA. `warmode/executor.py` ganhou um
estado persistido (`warmode/state.json`, fora do git — `{"active", "started_at"}`)
gravado toda vez que `run_war_mode`/`run_war_mode_revert` roda (independente de
sucesso por equipamento — reflete a intenção do operador, não o resultado SSH
por dispositivo, que já é reportado separadamente). Não substitui nem afrouxa a
etapa de confirmação (senha + lista de equipamentos + clique explícito) já
existente — só o gatilho (1 botão em vez de 2) mudou.

Novo `warmode/report.py`, rodado por um timer systemd próprio
(`init/flowguard-warmode-report.{service,timer}`, `OnUnitActiveSec=30min`,
instalado e habilitado nesta sessão) — deliberadamente um processo separado do
`flowguard.service`, mesma filosofia do resto do warmode (continua funcionando
mesmo com o daemon sob estresse, que é justo quando um DDoS real está
rolando). A cada disparo do timer: lê o estado do Modo Guerra direto do
arquivo (sem tocar o socket do daemon); se desligado, não faz nada; se ligado,
lê `flow_aggs`/`attacks` direto do SQLite (mesmo padrão de leitura ad-hoc já
usado por `cgi-bin/flowguard-ai.sh`), monta um prompt com tráfego atual,
ataques ativos e tempo decorrido, e pede um resumo panorâmico por IA — em que
fase o incidente está, quais links/prefixos estão sob ataque, tipos de
ataque predominantes, recomendação objetiva. Novo método `AIClient.war_mode_summary()`
em `ai/client.py` (mesmo padrão de `hourly_summary()`, mas com gatilho próprio,
não depende de `ai.hourly_report`). Se a IA falhar/estiver desabilitada, cai
num fallback só com os números (tráfego, contagem de ataques/regras) — nunca
deixa o operador sem nenhuma atualização só por causa da IA. Respeita
`alerts.whatsapp` do `config.yaml` (mesmo gate já usado pela notificação
imediata de ativação/reversão).

Validado ponta a ponta sem tocar em nenhum equipamento real: estado
simulado diretamente no arquivo (nunca via SSH), `run_report()` chamado
manualmente com `notifier.send_whatsapp` substituído por um mock — mensagem
gerada corretamente (elapsed time + resumo por IA real, usando dados reais de
produção). Timer testado via `systemctl start` (no-op confirmado com o Modo
Guerra desligado) e `systemctl list-timers` (próximo disparo em 30min). Ver
changelog do `flowguard-portal` (v1.26.0) pro lado do botão único/timer no
portal.

### v1.20.0 — 2026-07-04 — Mitigação automática + verificação de regras via SSH e 2º peer BGP na borda
- **Mitigação automática** (pedido do usuário): `mitigation_profiles.yaml` ganhou
  `auto_mode` por tipo de ataque — `off` (padrão, nada muda sozinho), `suggestion`
  (aplica sozinho o mesmo perfil do botão "Aplicar Sugestão", na abertura do
  ataque) ou `rtbh` (bloqueio total sozinho, igual ao botão "Mitigar"). Só tem
  efeito combinado com uma segunda trava por prefixo/cliente: `auto_mitigate:
  true` em `protected_prefixes.yaml`, campo que já existia (exposto há tempo na
  aba Monitor do portal e no `flowguard-cli monitor add --auto-mitigate`) mas
  nunca tinha sido lido por nenhum código — a engine de detecção nunca olhava
  pra ele. `BgpManager.auto_mitigate()` (novo) reaproveita a mesma lógica de
  `suggest_mitigation`/`ban`/`flowspec_add` já usada pelos botões manuais,
  chamado pela engine (`analyzer/engine.py`) só no momento em que um ataque
  ABRE (nunca a cada ciclo de 30s de um ataque já ativo, então nunca reaplica a
  mesma mitigação duas vezes). `flowguard-cli mitigation set --auto-mode
  off|suggestion|rtbh` e nova coluna "Automático" na aba Configuração >
  Mitigação do portal.
- Efeito colateral corrigido de passagem: a coluna `mitigated` da tabela
  `attacks` existia desde sempre no schema (e já era exibida como "sim"/"não"
  no CLI e no portal) mas nunca tinha código nenhum escrevendo nela — sempre
  mostrava "não". Agora `BgpManager.ban()`/`flowspec_add()` marcam
  `mitigated=1` sempre que uma regra é anunciada com sucesso associada a um
  `attack_id`, cobrindo automaticamente tanto a mitigação manual (botões
  "Mitigar"/"Aplicar Sugestão" já existentes) quanto a nova automática.
- 13 testes novos (`tests/test_auto_mitigation.py`), 104 no total.
- **Verificação de regras via SSH + segunda sessão BGP (peer PPPoE/CGNAT da borda)**:
  `bgp/manager.py` passou a suportar múltiplos peers BGP por nome lógico
  (`main`/`pppoe`, `bgp.peer_ip_pppoe` em `config.yaml`) no mesmo processo ExaBGP —
  `status(peer=...)`/`flowspec_add(..., peer=...)` resolvem o IP do peer
  correspondente; RTBH continua sempre no peer `main` (conceito de blackhole de
  borda, não se aplica a outros peers). Nova `BgpManager.verify_rule(rule_id)`
  confere via SSH (`routercfg/verify.py`, novo módulo) se uma regra de
  `flowspec_rules` está de fato presente no roteador — cobre o caso de o banco
  achar uma regra ativa/expirada/revertida e o roteador discordar. `flowguard-cli
  status` agora mostra as duas sessões BGP.

### v1.19.0 — 2026-07-03 — Reversão do Modo Guerra (revert_commands por equipamento)
- Pedido do usuário: um botão "Sair do Modo Guerra" no portal, pra desfazer
  os comandos aplicados sem precisar entrar manualmente em cada equipamento.
- Cada equipamento em `warmode.yaml` ganhou `revert_commands` (opcional,
  mesmo formato/regras de `commands` — `system-view` como primeiro item
  entra em modo de configuração automaticamente via `send_config_set`, ver
  fix da v1.18.0). `_run_device()` agora recebe um `mode` ("apply"/"revert")
  e escolhe a lista de comandos correspondente; equipamento sem
  `revert_commands` configurado retorna erro tratado (não trava os outros).
- Nova função pública `run_war_mode_revert()`, `flowguard-cli warmode
  revert` (mesma confirmação interativa do `run`), `list_devices()` ganhou
  `n_revert_commands`, audit log (`/var/log/flowguard-warmode-audit.jsonl`)
  e notificação WhatsApp ganharam um campo `mode` pra distinguir apply de
  revert.
- Validado com Netmiko mockado reproduzindo a sequência real de comandos do
  equipamento que motivou o pedido (`NE8000-PPPOE`/`HUAWEI-PPPOE-222`) e com
  Playwright real contra o backend de produção (contagens de comando batendo
  com `warmode.yaml` real, confirm button corretamente desabilitado quando
  `revert_commands` está vazio).

### v1.18.0 — 2026-07-03 — Corrige Modo Guerra travando em equipamentos com system-view
- **Bug real reportado pelo usuário**: um equipamento do Modo Guerra
  (sequência de comandos começando em `system-view`, ex. edição de ACL)
  falhava com `Pattern not detected: '<host>' in output` após ~27s.
  `warmode/executor.py` mandava cada comando via `send_command()`, que
  sempre espera o prompt de modo usuário (`<host>`) capturado no login —
  mas ao entrar em `system-view` o prompt vira modo config (`[host]`) e
  essa espera nunca é satisfeita.
- Corrigido: sequências que começam com `system-view` agora usam
  `send_config_set()`, que entra/sai do modo de configuração sozinho e
  reconhece os dois formatos de prompt. Linhas vazias/`#` (separadores de
  bloco de config, não comandos de verdade) são filtradas antes de enviar.
  Validado com Netmiko mockado reproduzindo a sequência real de comandos.
- **Nota:** um bug relacionado mas distinto (prompt de confirmação de
  commit ao SAIR do modo config, ver v1.17.0) já foi corrigido nos módulos
  `routercfg`/`edge_mitigation` trocando `device_type` pra `huawei_vrpv8` —
  não se aplica a este equipamento, que é hardware/versão de VRP diferente
  do NE8000 principal (confirmado com o usuário).

### v1.17.0 — 2026-07-02 — Corrige driver Netmiko: huawei_vrp não aplica config em NE8000 de carrier real
- **Bug real, achado e corrigido testando pela primeira vez uma aplicação de
  verdade (não só leitura) contra o NE8000 de produção**: `device_type:
  huawei_vrp` em `warmode.yaml` conecta e lê (`display ...`) sem problema,
  mas trava em qualquer `send_config_set` (aplicar mudança de config) — esse
  equipamento usa o modelo de configuração candidata do VRP (prompt some com
  `~`/`*` enquanto há mudança não commitada); ao sair do modo de
  configuração, o VRP pergunta interativamente `Uncommitted configurations
  found, commit them before exiting? [Y/N/C]`, e o driver `huawei_vrp` não
  sabe responder isso — trava até estourar o timeout
  (`Pattern not detected: '>' in output`). Corrigido trocando pra
  `device_type: huawei_vrpv8` (mesma família de driver Netmiko, mas com
  suporte ao fluxo de commit) — esse driver já manda `commit` sozinho antes
  de sair. `warmode.yaml.example` atualizado com essa observação.
- Validado ponta a ponta contra o equipamento real: aplicar uma regra de ACL
  de teste (prefixo RFC 5737, sem tráfego real) e reverter, tanto via
  `routercfg.apply` quanto via `clientguard/edge_mitigation.py` (mesmo
  equipamento, credenciais compartilhadas) — os dois caminhos de código
  agora aplicam config de verdade no NE8000BGP.
- Esse bug afetava IGUALMENTE o módulo `routercfg` (templates do portal) e a
  mitigação de borda do ClientGuard — nenhum dos dois nunca tinha conseguido
  aplicar uma mudança de config real antes desta correção, mesmo com
  credenciais certas, por causa do driver errado.

### v1.16.0 — 2026-07-02 — `origin` em flowspec_rules: base pra aba Regras unificada do portal
Usuário pediu que a aba "Regras" do portal mostre TODA interação com a borda
gerada tanto pelo FlowGuard quanto pelo ClientGuard, separado por aplicação.
`flowspec_rules` já guardava histórico completo (soft-delete via `active`,
nunca `DELETE`) cobrindo RTBH e FlowSpec juntos — só faltava saber QUEM pediu
cada regra, já que RTBH/FlowSpec proxied pelo ClientGuard (`block_add`) vive
na mesma tabela, só distinguível hoje por um `label` de texto livre.

- `collector/storage.py`: nova coluna `origin` (`'flowguard'` | `'clientguard'`,
  default `'flowguard'`) em `flowspec_rules`, com migração (`_migrate`) que
  também faz um backfill de melhor esforço nas linhas antigas (`origin =
  'clientguard' WHERE label LIKE '%ClientGuard%'`) — confirmado em produção:
  2 das 15 regras históricas foram reclassificadas corretamente.
- `bgp/manager.py`: `ban`/`flowspec_add` ganham parâmetro `origin: str =
  "flowguard"`, persistido na regra.
- `api/socket_server.py`: `_cmd_rules` ganha `history` (mesmo padrão de
  `_cmd_attacks`, default só ativas); `_cmd_ban`/`_cmd_flowspec_add` repassam
  `request.get("origin", "flowguard")`.
- `clientguard/socket_server.py` (repo `clientguard`) — `_cmd_block_add` agora
  manda `"origin": "clientguard"` no `flowspec_add` que pede pro FlowGuard.
- `flowguard-cli.py`: `rules --history` ganha coluna "App".
- 58 testes pytest continuam passando (nenhum teste específico de
  `flowspec_rules`/`origin` foi adicionado aqui — a suíte atual do FlowGuard
  cobre só `routercfg`; ver `clientguard` pro teste de `_cmd_block_add`).

### v1.15.0 — 2026-07-02 — Corrige nome do equipamento (NE8000BGP) em todos os templates
- **Bug real**: `routercfg/apply.py` (`DEFAULT_DEVICE_NAME`) e os 11 templates
  em `router_templates.yaml` ainda referenciavam `"NE8000 borda"` — nome
  placeholder usado quando o módulo foi criado, antes do equipamento real
  ser cadastrado em `warmode.yaml` como `NE8000BGP` (mesmo nome usado pela
  mitigação de borda do ClientGuard, ver `clientguard/edge_mitigation.py`).
  Com o nome desalinhado, toda aplicação de template falhava com
  "equipamento não encontrado" mesmo já com credenciais reais configuradas.
- Confirmado via CGI real: os 11 templates agora reportam `device_ready:
  true` (antes: `false` em todos).

### v1.14.0 — 2026-07-02 — Relatório consolidado: prefixos por operadora + histórico de regras FlowSpec/RTBH
- `discover_operator_routes()` (novo): numa única conexão SSH, lê a config
  BGP e consulta as rotas anunciadas/recebidas de cada peer EXTERNO (AS
  remoto diferente do local — `is_external_operator()`, nova função de
  filtro), sem abrir uma conexão por peer. `flowguard-cli routercfg
  operators [--received]` expõe isso.
- `flowguard-cli rules --history`: mostra TODAS as regras FlowSpec/RTBH já
  criadas (ativas ou não), lendo o SQLite direto em modo read-only — não
  passa pelo socket/daemon (mesmo padrão standalone do resto do
  `routercfg`), então funciona mesmo com o daemon fora do ar.
- 3 testes novos pra `is_external_operator()` (58 no total).

### v1.13.0 — 2026-07-02 — Visualização por operadora, descoberta de interfaces/VLANs, 5 templates novos
- `discover_all()` (novo) lê BGP + `display ip interface brief` + `display
  vlan brief` numa única conexão SSH (evita 3 conexões separadas pra montar
  a tela de descoberta do portal). `discover_bgp()` original continua
  existindo à parte, sem quebrar quem já usava só ela.
- `discover_peer_routes()` (novo): `display bgp routing-table peer {ip}
  advertised-routes`/`received-routes` — resolve diretamente o pedido de
  "ver redes/hosts advertidos por operadora": lista os prefixos reais sendo
  anunciados pra (ou recebidos de) um peer específico.
- 5 templates novos: `vlan_create_toggle` (criar/remover VLAN),
  `vlan_trunk_toggle` (add/remover VLAN de uma porta trunk),
  `interface_ip_toggle` (add/remover IP de uma interface),
  `vlan_subinterface_create`/`vlan_subinterface_remove` (sub-interface
  802.1Q) — os 3 primeiros com reversão simétrica via `undo_command_map`
  (mesmo mecanismo do BGP peer toggle), os 2 últimos com `commands`/
  `undo_commands` fixos (criar/remover não são simétricos: criar precisa de
  3 parâmetros, remover só de 2) — reversão automática desse par é best-effort
  (recria a sub-interface vazia, sem IP/VLAN) e depende mais do rollback
  point nativo do equipamento pra ser fiel, mesma ressalva já documentada
  pro template de interface anterior.
- Portal: qualquer campo do tipo `interface_name` em qualquer template (não
  só os novos) agora vira uma lista de interfaces reais depois da
  descoberta, não só os campos específicos de BGP.
- **Dois bugs reais encontrados e corrigidos testando pela primeira vez
  contra o roteador de borda real** (`warmode.yaml` foi preenchido em
  produção nesta mesma janela de trabalho — primeira validação de verdade
  do módulo `routercfg` contra hardware, não só mock):
  1. Nomes de interface podem começar com dígito (ex: `100GE0/1/54`,
     `25GE0/1/29(10G)`) — o regex de descoberta de interfaces assumia que
     todo nome começava com letra (`GigabitEthernet...`) e simplesmente não
     casava essas linhas, retornando uma lista vazia.
  2. Um bug mais sutil e mais sério: os regexes de VLAN/interface usavam
     `\s*`/`\s+` (que inclui `\n`) posicionados ANTES de um grupo de captura
     — quando a coluna seguinte vinha em branco (comum: VLAN sem nome/portas
     configurados), esse separador "atravessava" a quebra de linha e o grupo
     de captura seguinte recomeçava a casar já na PRÓXIMA linha, misturando
     o VID/status de uma VLAN com o conteúdo da vizinha. `^`/`$` com `re.M`
     não protegem contra isso — só ancoram início/fim de linha, não impedem
     um separador guloso no meio do padrão de cruzar pra outra linha. Fix:
     trocar `\s`/`\s+` por `[ \t]`/`[ \t]+` nesses dois regexes (espaço/tab
     não incluem `\n`). Testes de regressão novos cobrem exatamente esse
     cenário (VLAN com nome/portas em branco seguida de outra VLAN).
- 20 testes novos (55 no total) — incluindo os dois casos de regressão acima
  com amostras baseadas na saída real do equipamento (IDs/nomes genéricos,
  sem dado de cliente/operadora real).

### v1.12.0 — 2026-07-02 — Descoberta de BGP real: subir/derrubar operadora e anunciar/remover prefixo
- Novo `routercfg/discovery.py`: lê `display current-configuration
  configuration bgp` via SSH (mesmas credenciais de `warmode.yaml`) e extrai
  AS local, peers (IP, AS remoto, descrição, grupo, estado up/down conforme
  presença de `peer ... ignore`) e a lista de `network` statements anunciados
  — parsing por regex, só leitura, nunca aplica nada.
- Dois templates novos em `router_templates.yaml`:
  - `bgp_peer_toggle` — suspende/reativa a sessão com um peer específico via
    `peer {ip} ignore` / `undo peer {ip} ignore`, pensado pra manutenção com
    uma operadora sem mexer nas outras.
  - `bgp_prefix_advertise` — adiciona/remove um prefixo da lista de IPs
    advertidos via `network`/`undo network` (afeta todos os peers, não é
    filtro por operadora).
  Ambos com reversão exatamente simétrica (down↔up, announce↔withdraw) via
  `undo_command_map` (novo mecanismo genérico em `routercfg/templates.py` —
  mais confiável que os `undo_commands` fixos dos templates anteriores, já
  que aqui a reversão de cada opção é sempre a outra opção, sem precisar
  capturar estado anterior).
- **Bug real encontrado e corrigido nessa mesma implementação:** o
  `command_map`/`undo_command_map` guardava a string do comando já com
  placeholders (ex: `"peer {peer_ip} ignore"`), mas só o comando do
  *template* passava por `.format()` — o valor que substituía `{action_cmd}`
  entrava literal, com o placeholder `{peer_ip}` nunca resolvido. Corrigido
  com uma segunda passada em `_resolve_fields()` que formata os valores de
  `command_map`/`undo_command_map` depois que todos os campos (incluindo os
  derivados de `ipv4_cidr`) já foram resolvidos — não dá pra fazer isso numa
  passada só porque a ordem dos campos no YAML não é garantida.
- `flowguard-cli routercfg discover` (tabela de peers + prefixos) e
  `flowguard-routercfg.sh` (`action: "discover"`, novo) expõem a descoberta
  pro CLI e pro portal.
- 11 testes novos (`test_routercfg_discovery.py`, mais casos em
  `test_routercfg_templates.py`) — total 34 testes na suíte do FlowGuard.
  Mesma limitação já registrada: validado com SSH mockado, não contra
  hardware real (sem credenciais neste ambiente).

### v1.11.0 — 2026-07-02 — Configuração do roteador de borda via templates validados
- Novo módulo `routercfg/`: edição de config do roteador de borda por SSH
  (Netmiko) restrita a templates pré-definidos em `router_templates.yaml`
  (exportação de NetFlow, rota estática, ACL simples por prefixo, descrição/
  estado de interface) — nunca aceita comando livre vindo de formulário.
  Cada campo tem um tipo com validação estrita (`ipv4`, `ipv4_cidr`,
  `interface_name`, `text_safe`, `enum`, `int_range`); quebra de linha e
  separadores de comando (`;`, `|`, `` ` ``) são sempre rejeitados, mesmo
  dentro de um campo aparentemente inofensivo.
- Antes de aplicar, tenta criar um ponto de rollback nativo no equipamento
  (best-effort — segue em frente se a versão/plataforma não suportar). Toda
  mudança fica pendente de confirmação por alguns minutos (padrão 5); se o
  operador não confirmar, um processo separado reverte sozinho, preferindo o
  rollback point nativo e caindo para os `undo_commands` do próprio template
  (obrigatórios em todo template) se o rollback point não existir.
- Reaproveita as credenciais já cadastradas em `warmode.yaml` (mesmo arquivo
  do "Modo Guerra") em vez de duplicar um segundo cadastro de senha SSH.
- Exposto via `flowguard-cli routercfg list|preview|apply|confirm|revert|history`
  e consumido pelo portal (`flowguard-routercfg.sh`, protegido pela mesma
  senha do Modo Guerra).
- 23 testes automatizados novos (`tests/test_routercfg_templates.py`,
  `tests/test_routercfg_apply.py` — primeira suíte pytest do FlowGuard,
  incluindo casos de tentativa de injeção via campo) cobrindo validação de
  campos e o ciclo de vida completo (aplicar → confirmar/reverter →
  histórico) com o SSH mockado. Validado também via CLI real e Playwright
  real no portal — ver [[feedback-verify-with-real-browser]].
- **Limitação conhecida:** não há acesso às credenciais reais do equipamento
  neste ambiente (`warmode.yaml` ainda não preenchido) — o caminho de rede
  (Netmiko/SSH de fato) não foi validado contra hardware real, só mockado;
  a sintaxe VRP usada nos templates é a tipicamente documentada pra essa
  família de equipamento e deve ser conferida contra a versão de software
  real antes do primeiro uso em produção (mesma ressalva já feita antes para
  os comandos de NetStream passados manualmente ao operador).

### v1.10.0 — 2026-07-02 — Corrige crescimento descontrolado de flow_aggs (~9GB/dia) + robustez sob ataque
Revisão geral de código; correções em 4 frentes:

- **Cardinalidade da agregação (crítico)**: a chave de agregação incluía a porta de
  destino crua — ~65 mil portas efêmeras distintas/hora viravam ~2.8M de linhas/hora
  em `flow_aggs` (18GB em 2 dias; no ritmo antigo, a retenção de 14 dias
  estabilizaria em ~140GB, degradando toda query do portal). Duas mudanças em
  `flowguard.py` (`bucket_dst_port` + fusão de cauda longa):
  - Porta de destino só é gravada individualmente em prefixo protegido e se for
    well-known (<1024) — que é o que `attack_detail` usa pra caracterizar ataque;
    efêmeras colapsam em `dst_port=0`, prefixos de fallback sempre 0.
  - Destinos que não são clientes (fallback /24, ~9.6k distintos/ciclo): só os 100
    grupos mais volumosos do ciclo são gravados individualmente; o resto vira uma
    linha `outros` por protocolo. Totais (KPIs, gráfico por protocolo) não mudam —
    a linha agregada soma exatamente o que as individuais somariam.
  - Resultado medido em produção: ~35.000 → ~160 grupos/ciclo (-99.5%), gravação
    de 5-10s → alguns ms por ciclo. A detecção não muda em nada: ela sempre usou
    totais por (prefixo, protocolo) calculados em memória, não a tabela.
- **Retenção**: `prune_old_aggs` deletava tudo numa transação única — no primeiro
  prune real (14 dias de acúmulo) isso seguraria a conexão de escrita por minutos.
  Agora deleta em lotes de 100k com commit intermediário; `ANALYZE` saiu do prune
  horário e virou 1x/dia (`storage.analyze`).
- **Notificações fora do caminho crítico**: `evaluate_cycle` esperava (em série) a
  análise por IA, o WhatsApp e o webhook de cada ataque novo — numa onda de ataques
  simultâneos, o ciclo de agregação atrasava vários segundos e a fila de flows
  transbordava exatamente na hora errada. Agora saem via `fire_and_forget`
  (`asyncio.create_task` com log de erro no done-callback), e o warning de fila
  cheia é rate-limitado (1 a cada 10s com contagem, em vez de 1 por flow descartado).
- **Segurança**: `warmode.yaml` (senhas SSH dos equipamentos em texto puro) nascia
  world-readable (644, umask padrão) quando salvo pelo portal — agora `chmod 600`
  após toda gravação, e o arquivo existente foi corrigido.
- **Regressão do colapso de portas, encontrada e corrigida na validação**: com as
  efêmeras agregadas em `dst_port=0`, a linha do ataque passou a dividir o grupo com
  o tráfego legítimo do prefixo, e o ranking de hosts/origens de `attack_detail`/
  `top_hosts_for_prefix` (contagem simples de ciclos) elegia o host movimentado de
  sempre em vez do host atacado — `target_host` de um ataque de teste veio errado.
  Ranking agora pondera cada aparição por `bps_da_linha/(rank+1)` (a lista já vem
  ordenada por bytes); validado com o mesmo ataque sintético: host alvo em 1º e as
  origens sintéticas no topo. `occurrences` exibido não muda de significado. No
  prompt da análise por IA, `porta=0` agora vira "efêmeras (agregado)" — "porta 0"
  induzia a IA a analisar uma porta que não existe.

### v1.9.0 — 2026-07-02 — Migra WhatsApp de CallMeBot pra Evolution API self-hosted
- `notifier.py` reescrito: em vez da CallMeBot (serviço de terceiro), agora fala
  com uma **Evolution API self-hosted** (`/root/evolution-api/`, Docker Compose
  com Postgres+Redis) — conexão WhatsApp própria, sem depender de serviço
  externo. `send_whatsapp(message)` perdeu os parâmetros `phone`/`apikey`: o
  destino (grupo ou número) e a apikey da Evolution agora vêm de
  `/root/evolution-api/notify.yaml`/`.env`, compartilhados com o ClientGuard —
  só existe UMA sessão WhatsApp real.
- `config.yaml`: removidos `alerts.wa_dest`/`wa_apikey` (eram específicos da
  CallMeBot); `alerts.whatsapp`/`min_severity_wa` continuam controlando só se/
  quando alerta, não mais o destino.
- Portal ganhou uma tela nova ("📱 Alertas via WhatsApp" na aba Configuração,
  ver repo do portal) pra escanear o QR, ver status da conexão, escolher o
  grupo/número de destino e mandar mensagem de teste — sem precisar mexer em
  YAML/terminal pra reconfigurar.
- **Bug real encontrado e corrigido**: o `docker-compose.yml` da Evolution API
  apontava `CACHE_REDIS_URI` pro hostname `evolution-redis`, mas o serviço no
  compose se chama `redis` (Docker só resolve pelo nome do serviço ou
  `container_name`, não por string arbitrária) — a API subia e conectava no
  WhatsApp normalmente, mas todo envio de mensagem falhava silenciosamente
  (`redis disconnected` nos logs) porque o cache de sessão nunca conectava.
  Só apareceu ao testar o envio de verdade (mensagem de teste), não nos
  healthchecks/migração do Postgres, que não dependem do Redis.

### v1.8.0 — 2026-07-02 — Mitigação sugerida configurável: RTBH, discard ou rate-limit por tipo
- `bgp/flowspec.suggest_mitigation()` tinha as escolhas fixas no código: RTBH
  pra `ddos_volumetrico`/`anomalia_baseline` (sem porta/protocolo fixo pra
  casar em FlowSpec) e "discard" com limiar de pacote fixo pros 5 tipos de
  amplificação. Virou config editável por tipo (`mitigation_profiles.yaml`,
  novo, mesmo padrão de `detection_toggles.yaml`):
  - `kind`: `rtbh` (blackhole total, como antes) | `discard` (FlowSpec, só o
    tráfego que casa o padrão) | `rate_limit` (FlowSpec, não derruba nada, só
    limita a banda — opção nova, menos agressiva).
  - `pkt_len_min` (bytes, só `dns_amp`/`ntp_amp`) e `rate_limit_mbps`: os
    parâmetros de intensidade do filtro, antes hardcoded.
- Novos comandos no socket: `mitigation_profiles` (lista) e
  `set_mitigation_profiles` (aplica N mudanças numa leitura+escrita só, mesmo
  padrão atômico de `set_toggles`). `flowguard-cli mitigation list|set`.
- O botão "Mitigar" (aba Ataques) continua sempre RTBH — ação manual de
  emergência, deliberadamente sem essa configuração; só "Aplicar Sugestão"
  passou a honrar o perfil configurado.

### v1.7.0 — 2026-07-02 — set_toggles (bulk) — aplicar vários tipos de ataque de uma vez
- `save_feature_toggles`/socket `set_toggles` (novo) aplicam N mudanças numa
  única leitura+escrita, pra dar suporte ao botão "Aplicar novas
  configurações" do portal mandando 1 requisição com tudo em vez de N
  paralelas. Diferente do ClientGuard (threads de verdade, risco real de
  perder update sob concorrência), o socket aqui é asyncio de loop único sem
  `await` no meio do read-modify-write, então não havia race condition de
  fato — mas o formato em lote ainda reduz N reload_config()/escritas pra 1 e
  deixa os dois backends com a mesma superfície de comando. `set_toggle`
  (1 chave) e `flowguard-cli toggles set` continuam funcionando, delegando
  pra `set_toggles` internamente.

### v1.6.0 — 2026-07-02 — Alertas via WhatsApp (CallMeBot)
- `notifier.py` (novo) implementa o envio real de WhatsApp via CallMeBot
  (grátis, sem conta business — só requer ativar o bot uma vez no número de
  destino e gerar uma apikey). Substitui o placeholder "[WhatsApp pendente]"
  que só logava a mensagem sem enviar nada.
- `alerts.wa_apikey` (novo, `config.yaml`) complementa `alerts.wa_dest`/
  `min_severity_wa` já existentes.
- Ataque detectado (`notify_attack`, já existia) e ataque encerrado
  (`notify_attack_closed`, novo — antes só logava) disparam WhatsApp quando a
  severidade atinge `min_severity_wa`.
- Modo Guerra: `run_war_mode` agora avisa por WhatsApp ao final de cada
  execução (equipamentos OK/falha), lendo `alerts.whatsapp`/`wa_dest`/
  `wa_apikey` direto do `config.yaml` — continua standalone, não depende do
  `flowguard.service` estar de pé.
- Limitação conhecida da CallMeBot: a API responde 200 OK mesmo com apikey
  inválida (não há como distinguir "aceito" de "credencial errada" só pelo
  HTTP status) — testar com credenciais reais e confirmar recebimento no
  celular antes de confiar no alerta em produção.

### v1.5.0 — 2026-07-02 — Configurações via portal: liga/desliga tipos de ataque + limpar ativos
- `detection_toggles.yaml` (novo, separado do `config.yaml` — mesmo motivo de
  `protected_prefixes`/`whitelist`: editar via portal não pode reescrever o
  config principal) guarda o estado dos 7 tipos de ataque (`ddos_volumetrico`,
  `dns_amp`, `ntp_amp`, `ssdp_amp`, `memcached_amp`, `cldap_amp`,
  `anomalia_baseline`). Chave ausente/arquivo inexistente = habilitado, sem
  mudança de comportamento pra quem não usar a tela nova.
- `analyzer/engine.py` passou a pular a avaliação (`_evaluate`) de qualquer
  tipo desabilitado — a métrica factual (`any_amp_hit`, usada pra suprimir
  duplicidade com a anomalia de baseline) continua calculada independente do
  toggle, só a criação/atualização do registro em `attacks` é que é pulada.
- Coluna `dismissed` já existia no schema `attacks` mas nunca era escrita por
  nada — `storage.dismiss_attack`/`dismiss_all_active_attacks` (novo) marcam
  ataque(s) ativo(s) como dispensados sem fechar o registro (`ts_end`
  continua NULL): se a condição persistir, o próximo ciclo atualiza a MESMA
  linha em vez de reabrir/notificar de novo, já que a engine casa por
  `ts_end IS NULL`, não por `dismissed`.
- Novos comandos no socket: `toggles`, `set_toggle`, `dismiss_attack`,
  `dismiss_all_attacks`. `flowguard-cli toggles list|set`, `dismiss <id>`,
  `dismiss-all`.
- Portal: seção "Funções de Detecção" na aba Configuração (checkbox por tipo
  de ataque) e botão "Limpar hosts suspeitos" na aba Ataques — reaproveita
  `flowguard-attacks.sh` (`action: "dismiss"|"dismiss_all"`, novo).
- Validado contra o daemon em produção com tráfego sintético
  (`tools/synth_netflow.py dns_amp`): com o toggle `dns_amp` desabilitado, o
  mesmo tráfego não abriu ataque `dns_amp` mas ainda abriu
  `ddos_volumetrico` (toggle independente por tipo, confirmado) — depois
  dispensado via `dismiss` e confirmado fora da lista de "Ativos" mantendo o
  registro no histórico.

### v1.4.1 — 2026-07-02 — Suporte a editar equipamentos do Modo Guerra pelo portal
- `warmode/executor.py` ganhou `load_devices_masked()` (nunca devolve senha
  salva, só se ela existe) e `save_devices()` (mantém a senha já salva se o
  campo vier vazio, pra editar sem redigitar toda vez) — usados pela tela de
  configuração do portal (ver repo do portal).

### v1.4.0 — 2026-07-02 — Modo Guerra: botão de emergência multi-equipamento via SSH
- Novo módulo `warmode/`: em cenário de DDoS massivo, roda os comandos
  configurados via SSH (Netmiko, qualquer driver suportado) em vários
  equipamentos do datacenter (roteador de borda, mitigador...) de uma vez, em
  paralelo — um equipamento falhar não trava os outros.
- Config (`warmode.yaml`, com host/usuário/senha/comandos por equipamento)
  fica fora do git — só `warmode.yaml.example` é versionado. Nenhum comando
  real configurado ainda, precisa ser preenchido antes de usar.
- Toda execução grava audit log em `/var/log/flowguard-warmode-audit.jsonl`.
- `flowguard-cli warmode list|run` (run pede confirmação, `--yes` pula) e
  botão "🚨 Modo Guerra" no portal (ver repo do portal).
- Deliberadamente standalone: não depende do `flowguard.service` estar de pé.

### v1.3.0 — 2026-07-02 — Corrige RTBH: community e next-hop inválidos travavam o anúncio
- `rtbh_community` usava o ASN real do provedor numa community BGP padrão
  (16+16 bits) — um ASN de 4 bytes estoura esse formato e travava o ExaBGP
  silenciosamente ao montar a rota (nenhuma rota chegava a ser anunciada,
  mesmo com a sessão BGP up e sem nenhum erro visível). Trocado pelo valor de
  community que o roteador de borda realmente casa no filtro de aceitação.
- `nexthop_blackhole` estava como `0.0.0.0` — atributo NEXT_HOP inválido para
  BGP, descartado silenciosamente pelo roteador antes mesmo de avaliar a
  política de aceitação (nenhuma NOTIFICATION, contador de rotas recebidas
  ficava em zero). Trocado pelo IP do próprio speaker ("next-hop self"),
  padrão que o roteador reescreve para blackhole via política de import.
- Validado ponta a ponta em produção: rota de teste apareceu na tabela BGP do
  roteador de borda com a local-preference esperada, confirmando que a
  política de aceitação (community-filter + prefix-list) agora casa.

### v1.2.1 — 2026-07-02 — Mostra origem nas regras FlowSpec do CLI
- `flowguard-cli rules` ganhou coluna "Origem" (antes só mostrava "Alvo" =
  destino, então uma regra de bloqueio por origem aparecia como "-"). Base
  pro portal também expor bloqueio manual por IP de origem (ver repo do
  portal e do ClientGuard).

### v1.2.0 — 2026-07-02 — Indicador de status da sessão BGP (Up/Down)
- `bgp/speaker.py` passou a decodificar as notificações `neighbor-changes` que
  o ExaBGP já mandava (e eram descartadas) pra saber se a sessão com o
  roteador está `up`, `down` ou só `connected` (TCP ok, BGP ainda não
  estabelecido) — exposto via nova ação `status` no socket do speaker.
- `bgp/manager.py` ganhou `status()`; daemon expõe como comando `bgp_status`
  (e dentro do `dashboard` agregado).
- `flowguard-cli status` e o monitor interativo mostram "BGP (ExaBGP): Up"
  ou "Down/Idle".
- Precisou de `neighbor-changes;` no bloco `api` do `exabgp.conf` (não
  versionado neste repo, é config de sistema) — documentado em
  `/root/flowguard.md`.

### v1.1.1 — 2026-07-02 — Renumeração do link com o roteador de borda
- IP do link ponto-a-ponto com o roteador de borda mudou (endereço interno
  antigo desativado); `collector.bind_ip`, `bgp.router_id` e `bgp.peer_ip`
  em `config.yaml` atualizados para o novo endereçamento.
- `flowguard.service` reiniciado para religar o listener de NetFlow no novo
  IP — confirmado tráfego chegando normalmente após a troca.

### v1.1.0 — 2026-07-02 — Corrige contagem dupla de tráfego
- O roteador de borda exporta netstream `inbound` e `outbound` em todas as
  interfaces, então cada pacote real gerava 2 registros NetFlow (ingress +
  egress) do mesmo tráfego visto em dois pontos — bps/pps exibidos no portal
  ficavam ~2x acima do real.
- Parser passou a decodificar o campo NetFlow 61 (`flowDirection`) e a
  agregação só conta registros `ingress`, contando cada pacote exatamente
  uma vez.
- Validado com captura real do tráfego e em produção: total agregado caiu de
  ~45 Gbps para ~20,5 Gbps após a correção.

### v1.0.0 — 2026-07-01 — Correções operacionais
- `capacity_mbps` de um prefixo monitorado corrigido (estava 0).
- Retenção de flows aumentada de 7 para 14 dias.
- Falhas do ciclo de agregação e da análise de IA isoladas uma da outra.
- Publicado no GitHub.

### v0.6.0 — 2026-07-01 — Refinamentos de detecção e histórico
- Redução de falsos positivos no detector de anomalia de baseline.
- Janela de tempo selecionável no histórico de ataques.
- Detalhamento de ataques enriquecido (métricas por porta, linha do tempo).

### v0.5.0 — 2026-07-01 — Análise via IA
- Endpoint de análise sob demanda e relatório horário via Anthropic (Claude).

### v0.4.0 — 2026-07-01 — Granularidade de host
- Rastreamento de host `/32` individual dentro de prefixos protegidos.
- Detalhamento factual de ataques sem IA (breakdown por protocolo/porta e IPs
  de origem).

### v0.2.0 — 2026-07-01 — Direção in/out
- Agregação e schema passaram a separar tráfego de entrada e saída por
  prefixo.

### v0.1.0 — 2026-06-30 — Snapshot inicial
- Coletor NetFlow v9, engine de detecção (limiar fixo + anomalia por
  baseline EWMA), integração BGP/FlowSpec via ExaBGP, CLI e daemon.
