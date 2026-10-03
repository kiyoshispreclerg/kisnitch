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
| `daemon/main.go` | `daemon/main.c` | parcial | feito: flags `-version`, `-config-file`, `-log-file`, `-log-utc`, `-log-micro`, `-debug`, `-warning`, `-important`, `-error`, `-queue-num`, `-fw-config-file`; `setupLogging`, `overwriteLogging`, `loadDiskConfiguration`, `Rules.Path` padrão, `setupSignals`, `setupQueues` (só a fila principal), loop principal, `doCleanup`. Falta: `-ui-socket` e a fila de repetição (fase 5), `-workers` (sem workers, ver divergência 24), `-check-requirements`, flags de profiling |
| `daemon/main.go` (`onPacket`, `acceptOrDeny`, `applyDefaultAction`) | `daemon/intercept.c` | parcial | sem UI: conexão sem regra recebe a ação padrão, como upstream com a UI desconectada; perguntar à UI e estatísticas na fase 5 |
| `daemon/rule/rule.go` | `daemon/rules/rule.c` | parcial | `Rule`, `Create`, `String`, JSON; `Serialize`/`Deserialize` (protobuf) na fase 5 |
| `daemon/rule/operator.go` | `daemon/rules/rule.c` | portado | `Compile` e `Match` ramo a ramo, inclusive as alterações em `Data`/`Operand` |
| `daemon/rule/operator_lists.go` | `daemon/rules/lists.c` | portado | formatos, filtros, deduplicação, polling de 4 s |
| `daemon/rule/operator_aliases.go` | `daemon/rules/aliases.c` | parcial | `LoadAliases`, `GetAliasByIP`; `SerializeData` na fase 5 |
| `daemon/rule/loader.go` | `daemon/rules/loader.c` | parcial | tudo menos a parte de procmon de `EnableChecksums`/`HasChecksums` (fase 2) |
| `regexp` (Go stdlib, RE2) | `daemon/rules/regex.c` | portado | sintaxe Go traduzida para PCRE2 |
| `net` (`ParseIP`, `ParseCIDR`, `IP.String`, `IPNet.Contains`) | `common/netaddr.c` | portado | |
| `strings.ToLower`, `strings.EqualFold`, `unicode/utf8` | `common/unicode.c` | portado | |
| `encoding/json` (`Marshal`, `MarshalIndent`, decodificação) | `common/json_schema.c`, `common/json_util.c` | portado | escapes de HTML e UTF-8 inválido como o Go |
| `conman.Connection`, `procmon.Process`, `netstat.Entry` (campos usados pelas regras) | `daemon/conn.h` | estrutura | preenchidos pelas fases 2 e 3 |
| `daemon/main.go` (regras) | `daemon/main.c` | parcial | `LoadAliases`, flags `-rules-path` e `-no-live-reload`, carga das regras |
| `daemon/netstat/*.go` | `daemon/netstat.c` | portado | linhas lidas com as próprias regex do upstream (via `daemon/rules/regex.c`) |
| `daemon/netlink/socket.go`, `socket_linux.go` | `daemon/sockdiag.c` | portado | `GetSocketInfo`, `SocketGet`, `SocketsDump`, `GetSocketInfoByInode`, `SocketKill`, `KillSocket`, `KillSockets`, `KillAllSockets`, `FlushConnections`; netlink cru, sem libmnl |
| `daemon/netlink/ifaces.go` (`isPrivate`) | `daemon/sockdiag.c` | portado | |
| `vishvananda/netlink` `ConntrackTableFlush` | `daemon/sockdiag.c` (`conntrack_flush`) | portado | netlink cru; dispensa a libnetfilter_conntrack |
| `daemon/procmon/process.go`, `details.go` | `daemon/procmon/process.c` | parcial | tudo que o método proc usa; `GetExtraInfo` (descritores, I/O, status, statm, maps) e `Serialize` na fase 5 |
| `daemon/procmon/cache.go`, `cache_events.go` | `daemon/procmon/cache.c` | portado | |
| `daemon/procmon/find.go`, `parse.go` | `daemon/procmon/procmon.c` | parcial | método proc; o caminho do audit na fase 10 |
| `daemon/procmon/activepids.go`, `netlink/procmon/procmon.go` | `daemon/procmon/procmon.c`, `events.c` | portado | conector de eventos via netlink cru |
| `daemon/procmon/monitor/init.go` | `daemon/procmon/procmon.c` (`ks_procmon_init`) | parcial | só o método proc; ebpf (fase 9) e audit (fase 10) |
| `daemon/conman/connection.go` (`newConnectionImpl`, busca do processo) | `daemon/procmon/procmon.c` (`ks_procmon_resolve`) | parcial | método proc; ebpf (fase 9) e audit (fase 10) |
| `daemon/conman/connection.go` (`Parse`, `NewConnection(6)`, `parseDirection`) | `daemon/conn.c`, `daemon/intercept.c` | parcial | `DstHost`/`getDomains` (DNS) na fase 4; `Serialize` na fase 5 |
| `gopacket` v1.1.19 `layers/` (IPv4, IPv6 e extensões, AH, TCP, UDP, UDP-Lite, SCTP, ICMPv4/v6) e a decodificação preguiçosa de `packet.go` | `daemon/conn.c` | parcial | só as camadas que `conman` alcança; inclusive as falhas que ainda adicionam a camada. Ver divergência 22 |
| `daemon/netfilter/queue.go`, `queue.h`, `packet.go` | `daemon/queue.c` | portado | leitura no loop de eventos em vez de goroutine + canais; `SetRequeueVerdict` e `SetVerdictWithPacket` com a fase 5 |
| `daemon/dns/track.go` (`TrackAnswers`) | `daemon/intercept.c` | parcial | só o desvio "resposta DNS é aceita"; parse e cache na fase 4 (divergência 23) |
| `daemon/core/system.go` (`IPv6Enabled`) | `daemon/intercept.c` | portado | |
| `daemon/ui/client.go` (`DefaultAction`, `InterceptUnknown`), `config_utils.go` (`reloadConfiguration`: firewall e `FlushConnsOnStart`) | `daemon/intercept.c`, `daemon/main.c` (`start_firewall`) | parcial | só a primeira carga; recarga do config com a fase 5 |
| `daemon/firewall/rules.go` | `daemon/fw/fw.c` | parcial | `Init`, `Reload`, `Stop`, `IsRunning`, `Enable/DisableInterception`, `CleanRules`; `ReloadSystemRules`, `SaveConfiguration`, `ErrorsChan` na fase 8; `Serialize`/`Deserialize` na fase 5 |
| `daemon/firewall/nftables/{nftables,tables,chains,rules,monitor,utils}.go` | `daemon/fw/nft.c` | parcial | interceptação completa (tabela, cadeias, as 3 regras, limpeza por chave, `AreRulesLoaded`, `ReloadRulesCallback`); regras de sistema (`system.go`, `parser.go`, `rule_helpers.go`, `exprs/`) na fase 8 |
| `daemon/firewall/common/common.go` | `daemon/fw/nft.c` | parcial | verificador de regras (`NewRulesChecker`, `StopCheckingRules`, `SetRulesCheckerInterval`); `ErrChan`/`SendError` na fase 8 |
| `daemon/firewall/iptables/` | — | pendente | config com `"Firewall": "iptables"` usa nftables com aviso (divergência 30) |
| `time.Duration.String` (Go stdlib) | `common/duration.c` (`ks_format_duration`) | portado | |
| `crypto/md5`, `crypto/sha1` (Go stdlib) | `common/hash.c` | portado | sem OpenSSL |
| `proto/ui.proto` | `proto/ui.proto` | copiado | `tools/sync-proto.sh`; código em `common/pb/` gerado na fase 5 |
| `daemon/data/default-config.json`, `network_aliases.json`, `daemon/ui/testdata/*.json`, `daemon/rule/testdata/` | `tests/fixtures/upstream/` | copiado | `tools/sync-fixtures.sh` |

## Divergências conhecidas

Diferenças de comportamento em relação ao upstream, todas em casos de borda.
Cada uma precisa de justificativa; remover da lista quando corrigida.

| # | Onde | Upstream (Go) | Port | Motivo |
|---|---|---|---|---|
| 1 | `daemon/config.c` | `encoding/json` rejeita inteiros escritos como `2.0` ou `2e0` | aceita se o valor for inteiro e couber no tipo | o cJSON não guarda o literal do número. Mais permissivo, nunca rejeita config que o Go aceita |
| 2 | `daemon/config.c` | casamento de chaves sem diferenciar maiúsculas usa folding Unicode (ex.: `K` Kelvin U+212A casa com `k`) | folding só ASCII | chaves não ASCII que colidem com nomes de campo não ocorrem na prática |
| 3 | `daemon/config.c` | mensagem de erro de tipo é a de `json.UnmarshalTypeError` | `Campo.Sub: expected <tipo>, got <tipo JSON>` | mensagem só vai para o log/alerta; o formato próprio mostra o caminho completo do campo |
| 4 | `common/json_schema.c` | strings JSON com `\u0000` mantêm o NUL | string truncada no NUL | strings C; nenhum campo de config ou regra aceita NUL de forma útil (caminhos e nomes de `/proc` também não têm) |
| 5 | `daemon/config.c` | inteiros de 64 bits exatos | precisão de `double` acima de 2^53 | cJSON usa `double`; nenhum campo do config usa valores nessa faixa |
| 6 | `common/json_util.c` | limite de aninhamento JSON de 10000 | 1000 (`CJSON_NESTING_LIMIT`) | nenhum arquivo do upstream passa de 5 níveis |
| 7 | `common/json_util.c` | erros de sintaxe com offset em bytes | linha e coluna (às vezes um token depois do erro) | posição vem de onde o cJSON parou |
| 8 | `daemon/rules/rule.c` | pânico (derruba o daemon) quando o tipo do operador não aceita o valor do operando (ex.: `network` em `dest.ip`, `simple` em `dest.network`), em operadores aninhados dois níveis numa lista (não compilados) e em item de lista cuja regex falhou | o operador não casa | daemon rodando como root não pode cair por regra malformada; o teste diferencial conta esses casos à parte |
| 9 | `daemon/rules/lists.c` | linha `127.0.0.1` sem host numa lista de domínios causa pânico (`line[10:]` fora dos limites) | linha ignorada | idem |
| 10 | `daemon/rules/regex.c` | motor linear: nenhum padrão demora demais | limite de backtracking do PCRE2 (1 milhão de passos); ao estourar, conta como "não casa" | só padrões patológicos (ex.: `(a+)+$`) chegam perto |
| 11 | `daemon/rules/regex.c` | aceita `\p{Kawi}` e `\p{Nag_Mundari}` (Unicode 15) | rejeitados se o pcre2 do sistema for anterior ao Unicode 15 (< 10.43) | depende da versão do pcre2; scripts raríssimos em regras |
| 12 | `daemon/rules/regex.c` | grupo de flags seguido de quantificador aplica o quantificador ao átomo anterior (`a(?i)*`) | rejeitado | construção sem uso prático |
| 13 | `daemon/rules/regex.c` | tabelas Unicode do Go para `\p{...}`, `(?i)` e `strings.EqualFold` | tabelas do PCRE2 e da libc (locale C.UTF-8) | mesma fonte (Unicode); só muda entre versões do padrão. Sem locale C.UTF-8, só ASCII |
| 14 | `daemon/rules/loader.c` | nome de regra com `/` vira caminho fora do diretório de regras ao salvar | salvar é recusado com erro | nomes chegam da UI pela rede (fase 5): endurecimento de segurança |
| 15 | `daemon/rules/aliases.c` | `GetAliasByIP` percorre um mapa (ordem aleatória) | ordem do arquivo | determinístico; só difere se aliases se sobrepõem |
| 16 | `daemon/rules/lists.c`, `loader.c` | arquivos de qualquer tamanho | limite de 512 MiB por lista e 16 MiB por regra | proteção de memória |
| 17 | `daemon/netstat.c` | valor fora de `int64` numa linha de `/proc/net` derruba o daemon (`log.Fatal`) | a linha é ignorada | o daemon não deve cair por um parse |
| 18 | `daemon/procmon/process.c` | se nenhum caminho do executável abre, faz dump da memória do processo e acaba gravando o hash de um buffer vazio (`readMem` nunca preenche o retorno) | o checksum fica ausente | um hash fixo de "vazio" casaria regras por engano |
| 19 | `daemon/procmon/process.c` | `IsAbsPath("")` entra em pânico | caminho vazio é tratado como relativo | não derrubar o daemon |
| 20 | `daemon/procmon/events.c`, `procmon.c` | quatro goroutines processam eventos exec/exit em paralelo | tratados no loop principal, um por vez | arquitetura de um loop só (seção 4 do PORTING.md); a ordem dos eventos é preservada |
| 21 | `daemon/procmon/process.c` | checksums calculados na goroutine que achou o processo | calculados de forma síncrona | o pool de workers da seção 4 fica para quando houver veredictos assíncronos (fase 5); a medição da fase 3 (`docs/BENCH.md`) não mostrou necessidade antes disso |
| 22 | `daemon/conn.c` | o gopacket abre encapsulamentos GRE, EtherIP, MPLS-em-IP e túneis sobre UDP (VXLAN, Geneve, GTP...), e `parseDirection` pode pegar o TCP/UDP de dentro do túnel | só IP-em-IP (IPv4/IPv6) é aberto; nos outros a conexão fica sem camada de transporte (ação padrão) | túneis gerados localmente são raros, e decodificar Ethernet/MPLS/GRE num parser que roda como root aumentaria muito a superfície |
| 23 | `daemon/intercept.c` | resposta UDP da porta 53 só é aceita direto se o gopacket decodificar uma camada DNS válida; senão segue o caminho normal (quase sempre ação padrão) | qualquer UDP da porta 53 com payload é aceito | só até a fase 4, que traz o parser de DNS |
| 24 | `daemon/main.c`, `daemon/queue.c` | 16 workers; se nenhum pega o pacote em 1 ms, ele é aceito sem avaliação (marca 0) | cada pacote é avaliado no loop, em ordem; nunca aceito sem avaliação | arquitetura de um loop (seção 4 do PORTING.md); o upstream abre a rede sob carga |
| 25 | `daemon/fw/nft.c` | `MonitorInterval` negativo derruba o daemon (`time.NewTicker` entra em pânico) | o verificador é desligado, com aviso | não derrubar o daemon por config |
| 26 | `daemon/main.c` | se a fila não pode ser criada, `log.Fatal` sai com as regras de interceptação instaladas (sem `QueueBypass`, a rede fica bloqueada) | as regras são removidas antes de sair | não deixar a máquina sem rede por um erro de inicialização |
| 27 | `daemon/queue.c` | `go_callback` indexaria um payload vazio (pânico) | pacote sem payload é aceito | o kernel não manda pacote vazio; defensivo |
| 28 | `daemon/fw/nft.c` | mensagens de regra com `NLM_F_ECHO`; `ReloadRulesCallback` dorme 500 ms na goroutine do verificador | sem eco; os 500 ms são um timer do loop | não muda o estado do kernel; o loop não pode bloquear |
| 29 | `daemon/fw/nft.c` | listas de cadeias e regras com o buffer do google/nftables | respostas lidas com buffer de 64 KiB, e respostas pendentes de um dump interrompido são descartadas antes da próxima operação | robustez; mesmo resultado |
| 30 | `daemon/fw/fw.c` | `"Firewall": "iptables"` usa o binário iptables | usa nftables, com aviso (o upstream faz o mesmo quando o iptables não está disponível) | backend iptables ainda não portado |

## Bugs do upstream a relatar

Encontrados durante o port (docs/PORTING.md seção 8); o port reproduz o
comportamento, a não ser onde a tabela acima diz o contrário.

- Pânicos listados nas divergências 8 e 9.
- `Operator.Compile` com `user.name` troca `Data` pelo UID; ao salvar a regra
  em disco, o arquivo fica com o UID, e na próxima carga `user.Lookup("1000")`
  falha e a regra é descartada. O port reproduz.
- Regex sem diferenciação de maiúsculas é compilada com o padrão em
  minúsculas: escapes mudam de sentido (`\D` vira `\d`, `\W` vira `\w`,
  `\PL` vira `\pl`, que é inválido). O port reproduz.
- Regra `enabled` do tipo `list` no formato antigo (lista em `data` e `list`
  vazio) não é expandida em `loadRule`, e a lista vazia casa com tudo. O port
  reproduz.
- `cleanListsRule` só para o monitor do primeiro operador `lists` de uma
  regra `list`; os demais continuam rodando (goroutines vazadas). O port
  libera tudo ao substituir a regra.
- Timers de regras temporárias nunca são cancelados: após `Reload`, o timer
  antigo ainda apaga uma regra nova com o mesmo nome e a mesma duração. O
  port reproduz.
- `hexToIP` (netstat) decide entre IPv4 e IPv6 pelos 64 bits finais: um IPv6
  com a metade baixa zerada (ex.: `2001:db8::`, ou `::`) vira um IPv4 de 4
  bytes, e a busca em `/proc/net/*6` não casa. O port reproduz.
- `GetSocketInfo` devolve o UID do último socket com a mesma porta de origem,
  não o do socket encontrado. Normalmente o UID do netfilter sobrescreve. O
  port reproduz.
- O padrão de `/proc/net/packet` aceita só um dígito no índice da interface
  (interfaces >= 10 não são lidas). O port reproduz.
- `IsInStoreByPID` atualiza `LastSeen` numa cópia do item, então consultas
  nunca prolongam a vida de um processo no cache. O port reproduz.
- No método proc, `FindProcess` não monta a cadeia de pais (`GetParent`):
  sem eventos de exec (root), o operando `process.parent.path` nunca casa
  para processos vistos só pela conexão. O port reproduz.
- Sem eventos de processo (não root, ou kernel sem `CONFIG_PROC_EVENTS`), um
  PID reaproveitado por outro programa continua com os dados antigos no cache
  enquanto estiver vivo. O port reproduz.
- `nonSystemRules` (nftables/tables.go) pula uma cadeia só se o nome **e** a
  família da tabela forem diferentes (`&&`): conta as regras de todas as
  tabelas `inet` e de todas as tabelas chamadas `opensnitch`. Com outra
  tabela `inet` com regras (ex.: firewalld), a tabela `inet opensnitch`
  (vazia) fica para trás ao parar o daemon. O port reproduz (teste
  `upstream_keeps_table_if_inet_has_rules`).
- `-queue-num` sem `-fw-config-file`: as regras do nftables usam o
  `QueueNum` do config, mas o daemon escuta na fila da linha de comando. Sem
  `QueueBypass` a rede para; com ele, nada é interceptado. O port reproduz.
- Com `"Firewall": "iptables"` e `FwOptions` todo vazio, a primeira carga do
  config não vê mudança no firewall e ele nunca é iniciado. O port reproduz.
- `nfq_set_verdict2` sempre envia a marca: `SetVerdict` (conexões do próprio
  daemon e o timeout de 1 ms) zera a marca do pacote. O port reproduz para
  as conexões do próprio daemon.
- `KillSocket` (ação `reject`) destrói todos os sockets da família e
  protocolo com a mesma porta de origem, qualquer que seja o destino. O port
  reproduz.
- "Running on netfilter queue #%d" mostra o valor de `-queue-num`, não a fila
  em uso. O port reproduz.
- gopacket: num jumbograma IPv6 (opção jumbo com payload length 0) a camada
  seguinte é decodificada a partir do próprio cabeçalho hop-by-hop. O port
  reproduz.

## Decisões do port

- **JSON:** `cJSON` v1.7.19 vendorizado em `common/vendor/cjson/` (MIT), opção
  prevista na seção 2 do `docs/PORTING.md`. Elimina uma dependência de build;
  json-c não estava instalado na máquina de desenvolvimento.
- **Binários:** `kisnitchd` (daemon) e `kisnitch-gtk` (UI). Paths de
  configuração continuam os do upstream (`/etc/opensnitchd/`,
  `~/.config/opensnitch/`).
- **Regex:** pcre2 (dependência prevista), com a sintaxe Go traduzida em
  `daemon/rules/regex.c` para manter a semântica do upstream.
- **nftables:** libnftnl + libmnl (dependências previstas). As regras levam
  o mesmo user data do upstream (`opensnitch-key-interception`, bytes crus),
  então um daemon limpa as regras deixadas pelo outro.
- **Conntrack:** o caminho nftables do upstream não usa marcas de conntrack;
  quem evita reavaliar conexões já decididas são as próprias regras (só o
  SYN no TCP, `ct state new,related` no resto). O conntrack só aparece em
  `FlushConnections`, feito com netlink cru. A libnetfilter_conntrack não é
  usada.
- **Testes de integração:** `make test-integration` roda em network
  namespace próprio: como root, `unshare -n`; sem root, num user namespace
  (`unshare -Urn`), onde o kernel permite. Nunca na rede do host.
- **Versão:** `0.0.1+os1.8.0` (`config.mk`). Betas usarão til
  (`1.0.0~beta1+os...`) para o dpkg ordenar antes da versão final.
