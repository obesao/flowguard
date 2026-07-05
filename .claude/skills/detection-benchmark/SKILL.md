---
name: detection-benchmark
description: Pesquisa como ferramentas de referência (FastNetMon, Wanguard, etc.) detectam DDoS e compara com analyzer/engine.py do FlowGuard, gerando um gap-analysis acionável. Use quando o usuário pedir para estudar como outra ferramenta detecta ataques, ou para comparar/melhorar a detecção do FlowGuard com base numa referência externa.
---

# Pesquisar e comparar detecção de DDoS com ferramentas de referência

## Quando usar
- "aprenda como [ferramenta X] detecta DDoS e me mostre"
- "compare nossa detecção com [ferramenta X]"
- "tem algo que a gente podia aprender com [ferramenta X] pro nosso detector"

## Metodologia (não pular etapas)

1. **Pesquisar a documentação oficial da ferramenta de referência de verdade**
   (WebSearch + WebFetch nas páginas oficiais — a doc muda, não confiar em
   conhecimento de treino desatualizado). Estruturar a pesquisa em 4
   perguntas fixas, sempre as mesmas, pra comparação ficar apples-to-apples:
   - Quais métricas ela mede (pps/bps/flows totais, por protocolo, SYN,
     fragmentação, incoming vs outgoing separados)?
   - Qual a lógica de decisão (threshold fixo? baseline adaptativo ao vivo?
     ML? combinação OR/AND de sinais)?
   - Qual a granularidade de aplicação (global / hostgroup / por host /
     por subnet)?
   - O que ela dispara ao detectar (RTBH, FlowSpec, scrubbing, blocklist)?

2. **Ler o estado ATUAL do FlowGuard antes de comparar** — nunca assumir,
   sempre conferir os arquivos reais (podem ter mudado desde a última vez):
   - `analyzer/engine.py` — lógica de detecção implementada de fato
   - `config.yaml` seção `detection:` — limiares configurados hoje
   - `detection_toggles.yaml` — tipos de ataque que existem hoje

3. **Gap analysis, não resumo genérico.** Pra cada capacidade da
   referência que o FlowGuard não tem, decidir e registrar explicitamente:
   vale adotar (dado que isso é um ISP pequeno/médio, não uma operadora
   tier-1 com equipe de detecção dedicada)? Documentar tanto o que vale
   adotar quanto o que se decide deliberadamente NÃO adotar, e por quê —
   "não copiar tudo só porque a referência tem" é uma decisão válida.

4. **Terminar em plano acionável**, não em relatório de leitura. Se for
   virar trabalho de implementação de verdade, usar Plan mode antes de
   mexer em `analyzer/engine.py` (é o coração da detecção, mudança ali
   tem alto blast radius em produção).

## Conhecimento já levantado — FastNetMon (pesquisado em 2026-07-04)

**Arquitetura de coleta**: sFlow/SPAN (1-2s de detecção), NetFlow v5/v9/IPFIX
(5-30s — mesma faixa do FlowGuard), cloud flow logs.

**Motor de decisão**: threshold-based com lógica **OR** entre limiares
habilitados (não é ML, apesar do marketing usar "anomaly detection").
Contadores mantidos por host/hostgroup em 3 categorias, cada uma com par
`ban_for_X` (liga) + `threshold_X` (valor), **duplicado pra incoming e
outgoing separadamente**:
- Globais: pps, mbps, flows/s
- Por protocolo (pacotes): TCP/UDP/ICMP pps + **TCP SYN pps dedicado**
- Por protocolo (banda): TCP/UDP/ICMP mbps + TCP SYN mbps

**Granularidade**: global → hostgroup → host individual → prefixo CIDR,
via `fcli set hostgroup ... `.

**Baseline**: NÃO é adaptativo em tempo real. É uma ferramenta offline
(`fcli show baseline_per_host`) que lê métricas históricas do ClickHouse
depois de rodar 1 semana sem bloqueio (ou 10-15min pra um começo menos
representativo), devolve os valores de PICO observados, e a recomendação
oficial é usar **pico × 2-3** como threshold fixo daí em diante. Ou seja:
um cálculo único pra escolher bem um número estático, não um modelo vivo.

**Tipos de ataque reconhecidos**: floods UDP/TCP/ICMP, ataques de
protocolo (SYN/SYN-ACK/FIN), fragmentação IP, amplificação/reflexão
(DNS/NTP/SSDP/SNMP/GRE), multi-vetor.

**Mitigação disparada**: BGP RTBH/Blackhole, BGP FlowSpec, desvio pra
scrubbing center, blocklist.

Fontes: fastnetmon.com/ddos-detection-and-mitigation/,
fastnetmon.com/docs-fnm-advanced/fastnetmon-threshold-types/,
fastnetmon.com/docs-fnm-advanced/automated-baseline-calculation-with-fastnetmon-advanced/

## Gap analysis já feito (FastNetMon vs. FlowGuard, 2026-07-04)

- **FlowGuard está À FRENTE em baseline**: o detector de anomalia por EWMA
  (`analyzer/engine.py`) se adapta continuamente em produção; o do
  FastNetMon é um cálculo único offline que só ajuda a escolher um número
  fixo. Não regredir isso por causa da referência.
- **Gap real 1 — SYN flood como categoria própria**: FastNetMon trata SYN
  pps/mbps como um contador dedicado, separado de "TCP genérico". O
  FlowGuard hoje não tem um sinal específico pra SYN flood (cai dentro do
  volumétrico genérico, perde granularidade de diagnóstico/mitigação).
- **Gap real 2 — fragmentação IP como categoria própria**: idem, não
  existe hoje no FlowGuard.
- **Gap real 3 — thresholds outgoing separados**: o schema já distingue
  `direction` in/out (`flow_aggs`), mas os detectores de ataque hoje
  avaliam majoritariamente o lado incoming — outgoing anômalo (ex: cliente
  comprometido escaneando pra fora) é papel do ClientGuard, não do
  FlowGuard, o que é uma divisão de responsabilidade válida, não
  necessariamente um gap a fechar.
- **Decisão pendente de validar com o usuário**: vale a pena adicionar
  SYN flood e fragmentação como tipos de ataque dedicados (com toggle
  próprio em `detection_toggles.yaml`, igual aos outros 7 tipos), ou isso
  é complexidade demais pro volume de ataques reais já observado em
  produção? Não decidir sozinho — perguntar antes de implementar.
