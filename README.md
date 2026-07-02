# FlowGuard

**Versão atual: v1.9.0**

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

**Pendente:** `exabgp.service` ainda não está ativo em produção — aguardando
confirmação após aplicação da config BGP no roteador de borda real. Fase 5 (IA)
sem pipeline automático de eventos ainda, só análise sob demanda.

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
| `tools/synth_netflow.py` | Gerador de NetFlow sintético para testes |
| `collector/configio.py` | Leitura/gravação de `protected_prefixes.yaml`/`whitelist.yaml`/`detection_toggles.yaml`/`mitigation_profiles.yaml` |

## Changelog

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
