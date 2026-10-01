# Sincronização com o upstream

```
Versão upstream sincronizada: v1.8.0
Commit: b404c4c6316760fa7bc415509d3f8d747f7dc9cc
Data do sync: 2026-10-01
```

Upstream: <https://github.com/evilsocket/opensnitch>, submodule em `upstream/`
(somente leitura). Para atualizar, ver `docs/PORTING.md` seção 7.2 e
`tools/upstream-diff.sh`.

## Mapeamento

Status: `portado` (comportamento completo), `parcial` (o que falta está na
coluna de notas), `estrutura` (só os dados; o comportamento vem em fase
posterior), `copiado` (arquivo trazido sem tradução), `pendente`.

| Upstream | Port | Status | Notas |
|---|---|---|---|
| `daemon/ui/config/config.go` | `daemon/config.c` | portado | `Parse`, `Load`, `Save`, `Marshal`; todos os campos de `Config` |
| `daemon/procmon/audit/config.go` (`Config`) | `daemon/config.c` | estrutura | uso na fase 10 |
| `daemon/procmon/ebpf/config.go` (`Config`) | `daemon/config.c` | estrutura | uso na fase 9 |
| `daemon/statistics/stats.go` (`StatsConfig`) | `daemon/config.c` | estrutura | uso na fase 5 |
| `daemon/log/loggers/logger.go` (`LoggerConfig`) | `daemon/config.c` | estrutura | uso na fase 10 |
| `daemon/ui/config_utils.go` (`loadDiskConfiguration`, `loadConfiguration`) | `daemon/config.c` (`ks_config_reload`) | parcial | recarga mantém o config anterior em erro de parse; aplicar cada opção recarregada vem com o módulo de cada fase; monitoramento por inotify na fase 1 |
| `daemon/ui/config_utils.go` (`reloadConfiguration`, parte de log) | `daemon/main.c` (`apply_log_config`) | portado | |
| `daemon/log/log.go` | `common/log.c` | portado | mesmo formato de linha, rótulos e cores |
| `time.ParseDuration` (Go stdlib) | `common/duration.c` | portado | tradução linha a linha de `src/time/format.go` (Go 1.23) |
| `daemon/rule/rule.go` (`Once`, `Restart`, `Always`) | `common/duration.h` | portado | |
| `daemon/rule/loader.go` (`isTemporary`) | `common/duration.c` (`ks_rule_duration_kind`) | portado | |
| `daemon/main.go` | `daemon/main.c` | parcial | feito: flags `-version`, `-config-file`, `-log-file`, `-log-utc`, `-log-micro`, `-debug`, `-warning`, `-important`, `-error`; `setupLogging`, `overwriteLogging`, `loadDiskConfiguration`, `Rules.Path` padrão. Falta: as demais flags e o loop principal (fases 1–5) |
| `proto/ui.proto` | `proto/ui.proto` | copiado | `tools/sync-proto.sh`; código em `common/pb/` gerado na fase 5 |
| `daemon/data/default-config.json`, `daemon/ui/testdata/*.json` | `tests/fixtures/upstream/` | copiado | `tools/sync-fixtures.sh` |

## Divergências conhecidas

Diferenças de comportamento em relação ao upstream, todas em casos de borda.
Cada uma precisa de justificativa; remover da lista quando corrigida.

| # | Onde | Upstream (Go) | Port | Motivo |
|---|---|---|---|---|
| 1 | `daemon/config.c` | `encoding/json` rejeita inteiros escritos como `2.0` ou `2e0` | aceita se o valor for inteiro e couber no tipo | o cJSON não guarda o literal do número. Mais permissivo, nunca rejeita config que o Go aceita |
| 2 | `daemon/config.c` | casamento de chaves sem diferenciar maiúsculas usa folding Unicode (ex.: `K` Kelvin U+212A casa com `k`) | folding só ASCII | chaves não ASCII que colidem com nomes de campo não ocorrem na prática |
| 3 | `daemon/config.c` | mensagem de erro de tipo é a de `json.UnmarshalTypeError` | `Campo.Sub: expected <tipo>, got <tipo JSON>` | mensagem só vai para o log/alerta; o formato próprio mostra o caminho completo do campo |
| 4 | `daemon/config.c` | strings com `\u0000` mantêm o NUL; UTF-8 inválido vira U+FFFD | string truncada no NUL; bytes inválidos preservados | strings C; nenhum campo do config aceita esses valores de forma útil |
| 5 | `daemon/config.c` | inteiros de 64 bits exatos | precisão de `double` acima de 2^53 | cJSON usa `double`; nenhum campo do config usa valores nessa faixa |
| 6 | `common/json_util.c` | limite de aninhamento JSON de 10000 | 1000 (`CJSON_NESTING_LIMIT`) | nenhum arquivo do upstream passa de 5 níveis |
| 7 | `common/json_util.c` | erros de sintaxe com offset em bytes | linha e coluna (às vezes um token depois do erro) | posição vem de onde o cJSON parou |

## Decisões do port

- **JSON:** `cJSON` v1.7.19 vendorizado em `common/vendor/cjson/` (MIT), opção
  prevista na seção 2 do `docs/PORTING.md`. Elimina uma dependência de build;
  json-c não estava instalado na máquina de desenvolvimento.
- **Binários:** `kisnitchd` (daemon) e `kisnitch-gtk` (UI). Paths de
  configuração continuam os do upstream (`/etc/opensnitchd/`,
  `~/.config/opensnitch/`).
- **Versão:** `0.0.1+os1.8.0` (`config.mk`).
