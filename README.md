# FlowGuard

**Versão atual: v1.2.1**

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

**Pendente:** `exabgp.service` ainda não está ativo em produção — aguardando
confirmação após aplicação da config VRP no NE8000 real. Fase 5 (IA) sem
pipeline automático de eventos ainda, só análise sob demanda.

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
| `tools/synth_netflow.py` | Gerador de NetFlow sintético para testes |

## Changelog

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
