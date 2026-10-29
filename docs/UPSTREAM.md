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
posterior), `copiado` (arquivo trazido sem tradução), `pendente`. Uma linha `parcial`,
`estrutura` ou `pendente` só fica assim com "fora, justificado" na coluna de
notas (o que não foi portado e por quê).

| Upstream | Port | Status | Notas |
|---|---|---|---|
| `daemon/ui/config/config.go` | `daemon/config.c` | portado | `Parse`, `Load`, `Save`, `Marshal`; todos os campos de `Config` |
| `daemon/procmon/audit/config.go` (`Config`) | `daemon/config.c` | portado | |
| `daemon/procmon/audit/client.go`, `parse.go` | `daemon/procmon/audit.c` | portado | leitura do socket do audisp no loop (reconexão a cada 30 s por timer), regras com `auditctl`, a regex de campos do upstream pelo `daemon/rules/regex.c`; divergências 100 e 101. `EventChan`/`StartChannel` não têm consumidor no upstream |
| `daemon/procmon/ebpf/config.go` (`Config`) | `daemon/config.c` | estrutura | fora, justificado: o uso é do método ebpf, que a fase 9 (adiada em 2026-10-29) traz |
| `daemon/statistics/stats.go` (`StatsConfig`) | `daemon/config.c` | portado | aplicado por `daemon/stats.c` |
| `daemon/log/loggers/logger.go` (`LoggerConfig`) | `daemon/config.c` | portado | |
| `daemon/log/loggers/*.go` (`LoggerManager`, `Remote`, `RemoteSyslog`, `Syslog`) | `daemon/loggers.c` | portado | fila e workers em threads (destacadas: parar não espera conexão nem resolução de nome); o `log/syslog` local falado direto no `/dev/log`. Divergências 96 a 98 |
| `daemon/log/formats/*.go` (RFC 5424, RFC 3164, CSV, JSON) | `daemon/logformats.c` | portado | o JSON da conexão é o `encoding/json` da struct gerada (`omitempty`), não o protojson |
| `daemon/ui/config_utils.go` (`loadDiskConfiguration`, `loadConfiguration`, `reloadConfiguration`, `getSocketPath`) | `daemon/uiclient.c` | portado | inclusive o monitoramento do arquivo (inotify, como o fsnotify: escrita e remoção). `Server.Loggers`, `TasksOptions` e `Audit` aplicados (fase 10). Fora, justificado: `Ebpf` (fase 9 adiada) e `Internal.GCPercent` (não se aplica a C) |
| `daemon/ui/config_utils.go` (`reloadConfiguration`, parte de log) | `daemon/uiclient.c` | portado | |
| `daemon/log/log.go` | `common/log.c` | portado | mesmo formato de linha, rótulos e cores |
| `time.ParseDuration` (Go stdlib) | `common/duration.c` | portado | tradução linha a linha de `src/time/format.go` (Go 1.23) |
| `daemon/rule/rule.go` (`Once`, `Restart`, `Always`) | `common/duration.h` | portado | |
| `daemon/rule/loader.go` (`isTemporary`) | `common/duration.c` (`ks_rule_duration_kind`) | portado | |
| `daemon/main.go` | `daemon/main.c` | parcial | feito: flags `-version`, `-config-file`, `-log-file`, `-log-utc`, `-log-micro`, `-debug`, `-warning`, `-important`, `-error`, `-queue-num`, `-fw-config-file`; `setupLogging`, `overwriteLogging`, `loadDiskConfiguration`, `Rules.Path` padrão, `setupSignals`, `setupQueues` (só a fila principal), `initSystemdResolvedMonitor`, loop principal, `doCleanup`. Feito na fase 5: `-ui-socket`, `ui.NewClient` e `Connect`, estatísticas, alertas de erro da fila e do `-process-monitor-method`; a fila de repetição não existe (divergência 37). Fora, justificado: `-workers` (sem workers, divergência 24), `dns.ListenerEbpf` (fase 9 adiada), `-check-requirements` (só imprime um relatório da configuração do kernel e sai; não afeta a interceptação, e o relatório existe em função do ebpf) e as flags de profiling (`-cpu-profile`, `-mem-profile`: são do `pprof` do Go) |
| `daemon/main.go` (`onPacket`, `acceptOrDeny`, `applyDefaultAction`) | `daemon/intercept.c` | portado | pergunta à UI com veredicto adiado em vez da fila de repetição (divergência 37) |
| `daemon/rule/rule.go` | `daemon/rules/rule.c`, `daemon/protocol.c` | portado | `Serialize`/`Deserialize` em `protocol.c` (divergência 46) |
| `daemon/rule/operator.go` | `daemon/rules/rule.c` | portado | `Compile` e `Match` ramo a ramo, inclusive as alterações em `Data`/`Operand` |
| `daemon/rule/operator_lists.go` | `daemon/rules/lists.c` | portado | formatos, filtros, deduplicação, polling de 4 s |
| `daemon/rule/operator_aliases.go` | `daemon/rules/aliases.c` | portado | `SerializeData` não é chamado em lugar nenhum do upstream; não portado |
| `daemon/rule/loader.go` | `daemon/rules/loader.c` | portado | `EnableChecksums` liga o cálculo no procmon (`ks_events_set_compute_checksums`) |
| `regexp` (Go stdlib, RE2) | `daemon/rules/regex.c` | portado | sintaxe Go traduzida para PCRE2 |
| `net` (`ParseIP`, `ParseCIDR`, `IP.String`, `IPNet.Contains`) | `common/netaddr.c` | portado | |
| `strings.ToLower`, `strings.EqualFold`, `unicode/utf8` | `common/unicode.c` | portado | |
| `encoding/json` (`Marshal`, `MarshalIndent`, decodificação) | `common/json_schema.c`, `common/json_util.c` | portado | escapes de HTML e UTF-8 inválido como o Go |
| `conman.Connection`, `procmon.Process`, `netstat.Entry` (campos usados pelas regras) | `daemon/conn.h` | portado | preenchidos pelo procmon (fase 2) e pelo `daemon/conn.c` (fase 3) |
| `daemon/main.go` (regras) | `daemon/main.c` | portado | `LoadAliases`, flags `-rules-path` e `-no-live-reload`, carga das regras |
| `daemon/netstat/*.go` | `daemon/netstat.c` | portado | linhas lidas com as próprias regex do upstream (via `daemon/rules/regex.c`) |
| `daemon/netlink/socket.go`, `socket_linux.go` | `daemon/sockdiag.c` | portado | `GetSocketInfo`, `SocketGet`, `SocketsDump`, `GetSocketInfoByInode`, `SocketKill`, `KillSocket`, `KillSockets`, `KillAllSockets`, `FlushConnections`; netlink cru, sem libmnl |
| `daemon/netlink/socket_packet.go` (`SocketDiagPacket`, `PacketDiagMsg.deserialize`) | `daemon/sockdiag.c` (`ks_sock_dump_packet`, `ks_packet_diag_parse`) | portado | a leitura por deslocamentos fixos, com o índice da interface truncado (bugs a relatar) |
| `daemon/netlink/socket_xdp.go`, `vishvananda/netlink` `SocketDiagXDP` | `daemon/sockdiag.c` (`ks_sock_dump_xdp`) | portado | só os campos que o `sockets-monitor` usa (inode, cookie, interface, UID) |
| `daemon/netlink/ifaces.go` (`isPrivate`) | `daemon/sockdiag.c` | portado | |
| `vishvananda/netlink` `ConntrackTableFlush` | `daemon/sockdiag.c` (`conntrack_flush`) | portado | netlink cru; dispensa a libnetfilter_conntrack |
| `daemon/procmon/process.go`, `details.go` | `daemon/procmon/process.c` | parcial | tudo que o método proc usa, `GetExtraInfo` (`ks_proc_get_extra_info`: ambiente, descritores, I/O, status, stat, stack, maps, statm) e o `json.Marshal(Process)` das tarefas (`ks_proc_json`, com `time.Time` em RFC 3339 local e os mapas ordenados). Fora, justificado: `Serialize` (protobuf), só usado pelos eventos de kernel do ebpf (fase 9 adiada); `DumpImage` não é usado (ver divergência sobre checksums) |
| `daemon/procmon/cache.go`, `cache_events.go` | `daemon/procmon/cache.c` | portado | |
| `daemon/procmon/find.go`, `parse.go` | `daemon/procmon/procmon.c` | portado | métodos proc e audit (`getPIDFromAuditEvents`) |
| `daemon/procmon/activepids.go`, `netlink/procmon/procmon.go` | `daemon/procmon/procmon.c`, `events.c` | portado | conector de eventos via netlink cru |
| `daemon/procmon/monitor/init.go` | `daemon/procmon/procmon.c` (`ks_procmon_reconfigure`, `ks_procmon_monitor_init`, `ks_procmon_monitor_end`) | parcial | `ReconfigureMonitorMethod`, `Init`, `End` com o rollback de método; ebpf (fase 9 adiada: fora, justificado) falha com o erro do tipo certo e cai no proc; audit inicia (divergência 100) |
| `daemon/conman/connection.go` (`newConnectionImpl`, busca do processo) | `daemon/procmon/procmon.c` (`ks_procmon_resolve`) | parcial | métodos proc e audit; ebpf fica fora (fase 9 adiada). O bloco do audit em `newConnectionImpl` consulta `GetEventByPid(pid)` com o pid ainda -1 e nunca acha nada (código morto, não portado): o audit entra pela busca do PID pelo inode |
| `daemon/conman/connection.go` (`Parse`, `NewConnection(6)`, `parseDirection`, `getDomains`, `To`, `String`, `Serialize`) | `daemon/conn.c`, `daemon/intercept.c`, `daemon/protocol.c` | portado | |
| `gopacket` v1.1.19 `layers/` (IPv4, IPv6 e extensões, AH, TCP, UDP, UDP-Lite, SCTP, ICMPv4/v6, a escolha da camada seguinte por porta de `ports.go`/`UDP.NextLayerType`) e a decodificação preguiçosa de `packet.go` | `daemon/conn.c` | parcial | fora, justificado: só as camadas que `conman` e `dns` alcançam; inclusive as falhas que ainda adicionam a camada. Ver divergência 22 |
| `gopacket` v1.1.19 `layers/dns.go` (`DecodeFromBytes`, `decodeName`, `decodeRData`, `decodeCharacterStrings`, `decodeOPTs`) | `daemon/dns/parse.c` | portado | só decodificação (o upstream não serializa DNS). Leituras que no Go entram em pânico (e o gopacket recupera sem adicionar a camada) são erros; os campos fixos da pergunta podem ler até a capacidade do slice, como no Go. Ver divergências 32 e 33 |
| `daemon/netfilter/queue.go`, `queue.h`, `packet.go` | `daemon/queue.c` | portado | leitura no loop de eventos em vez de goroutine + canais; `SetRequeueVerdict` não é usado (divergência 37); `SetVerdictWithPacket` não é chamado pelo upstream |
| `daemon/dns/track.go` (`TrackAnswers`, `Track`, `Host`, `HostOr`) | `daemon/dns/cache.c` | portado | cache limitado (divergência 31) |
| `daemon/dns/parse.go` (`GetQuestions`) | `daemon/dns/cache.c` (`ks_dns_query_domain`) | portado | |
| `daemon/dns/systemd/monitor.go`, `daemon/main.go` (`initSystemdResolvedMonitor`) | `daemon/dns/resolved.c` | portado | sem libsystemd; reconexão diferente (divergência 34) |
| `github.com/varlink/go` v0.4.0 (`NewConnection`, `Send` e o callback de recebimento) | `daemon/dns/resolved.c` | portado | só o cliente, só o que o monitor usa |
| `daemon/dns/ebpfhook.go` (`ListenerEbpf`) | — | pendente | fora, justificado: fase 9 (EBPF=1), adiada por decisão do usuário em 2026-10-29 |
| `daemon/core/system.go` (`IPv6Enabled`) | `daemon/intercept.c` | portado | |
| `daemon/ui/client.go` | `daemon/uiclient.c` | portado | `NewClient`, `Connect`, `poller`, `connect`, `openSocket` (TLS com `TLS=1`, divergência 39), `disconnect`, `ping`, `Ask`, `PostAlert`, `DefaultAction`, `DefaultDuration`, `Connected`, `IsAsking`, `InterceptUnknown`, `GetFirewallType`, `monitorConfigWorker`. Conexão: `common/grpc/` |
| `daemon/ui/notifications.go` | `daemon/uiclient.c` | portado | `getClientConfig` (com `SystemFirewall`), `Subscribe`, `listenForNotifications`, `sendNotificationReply` e todos os `handleAction*` (o JSON das tarefas aceita `name` e `Name`, como o decodificador do Go; a UI manda minúsculas); `handleActionReloadFw` grava o `system-fw.json` e responde com os erros da recarga (ou OK depois de 2 s). `handleActionTaskStart`/`Stop` com as três tarefas da UI (divergências 41, 86 a 88) |
| `daemon/ui/notifications_tasks.go` | `daemon/uiclient.c` (`on_task_result`, `add_task`) | portado | `monitorTaskEvents` (resposta à notificação se o id for > 10000, senão alerta), `monitorSockets`, `monitorNode`, `monitorProcessDetails`; `monitorTaskManager` não tem o que fazer sem canais. Os alertas das tarefas também vão para os loggers |
| `daemon/tasks/main.go`, `base/main.go`, `doc.go` | `daemon/tasks/tasks.c` | portado | `TaskManager` (`AddTask`, `RemoveTask`, `GetTask`, `StopAll`, `StopTempTasks`, `Stop`), os ids de `base`; cada tarefa é um timer do loop em vez de goroutine e canais. `UpdateTask` não tem uso; `PauseAll`/`ResumeAll` não têm chamadores e as tarefas não os implementam (TODO no upstream) |
| `daemon/tasks/pidmonitor/main.go` | `daemon/tasks/pidmon.c` | portado | divergência 86 |
| `daemon/tasks/nodemonitor/main.go` | `daemon/tasks/nodemon.c` | portado | o JSON de `syscall.Sysinfo_t` com os campos de linux/amd64 (`Pad_cgo_0`, `X_f`, `Pad_cgo_1`) ou de 32 bits; a lista de campos veio do pacote `syscall` e falta conferir contra o daemon Go no job `interop-ui` |
| `daemon/tasks/socketsmonitor/*.go` | `daemon/tasks/sockmon.c` | portado | divergências 86, 87 e 89 |
| `daemon/tasks/load.go`, `config/main.go`, `monitor.go`, `utils.go` | `daemon/tasks/load.c` | portado | `LoadTaskFile`, `ReloadTaskFile` (sem uso), `loadDiskTasks`, `loadDiskTask`, `Loader.Load`, `LoadTaskData`, `AddWatches`/`RemoveWatch` e o `liveReloadWorker` com inotify no loop; divergências 90 e 95 |
| `daemon/tasks/looptask/main.go` | `daemon/tasks/looper.c` | portado | |
| `daemon/tasks/scheduler/scheduler.go` | `daemon/tasks/scheduler.c` | portado | `time.Parse` de `15:04:05`/`15:04` com as regras do Go (hora de um ou dois dígitos, fração de segundo aceita); timers do loop no lugar dos tickers |
| `daemon/tasks/iocscanner/*.go` (`config`, `tools/base`, `executer`, `yara`, `dpkg`, `generic`) | `daemon/tasks/iocscanner.c` | portado | processos com `posix_spawnp` e a saída lida no loop; divergências 41, 91 e 92 |
| `daemon/tasks/downloader/*.go` | `daemon/tasks/downloader.c` | portado | só com `CURL=1` (libcurl numa thread, as listas em paralelo); sem ele a tarefa não inicia. Divergências 93 e 94 |
| `daemon/ui/alerts.go` | `daemon/uiclient.c`, `daemon/protocol.c` (`ks_pb_alert_text`) | portado | alertas de texto e a fila do `alertsDispatcher`; sem gzip (divergência 38). Fora, justificado: os alertas com processo ou conexão só são gerados pelos eventos do ebpf (fase 9 adiada) |
| `daemon/ui/auth/auth.go` | `common/grpc/tls.c` (`ks_tls_client_new`), `daemon/uiclient.c` (`open_socket`) | portado | OpenSSL, só com `TLS=1`: raízes só dos arquivos dados (CA e certificado do servidor, avisos se ilegíveis), `SkipVerify`, certificado de cliente no `tls-mutual`; o nome verificado é o host do endereço (só SANs, como o Go; um certificado da lista vale como âncora mesmo sem ser autoassinado); ALPN `h2`. `ClientAuthType` só vale num servidor e é ignorado no cliente, como no upstream. Testado contra o grpc core do Python e com o daemon Go 1.6.5 contra a nossa UI (`tests/integration/tls.sh`) |
| `ui/opensnitch/auth/__init__.py` (`get_tls_credentials`) | `common/grpc/tls.c` (`ks_tls_server_new`), `ui/main.c`, `ui/server.c` | portado | com CA, o cliente precisa apresentar um certificado que ela assina |
| `daemon/statistics/stats.go`, `event.go` | `daemon/stats.c` | portado | sem workers (contagem no loop); `SetLoggers` e o `logger.Log` de cada conexão; divergência 45 |
| `daemon/core/system.go` (`GetHostname`, `GetKernelVersion`) | `daemon/uiclient.c` | portado | |
| `google.golang.org/grpc` (cliente: `Dial`, keepalive, prazos, status) | `common/grpc/grpc.c` | portado | só o que o protocolo usa; ver `docs/PROTOCOL.md` |
| `daemon/firewall/rules.go` | `daemon/fw/fw.c` | portado | `Init` (iptables se o binário funciona, senão nftables; tipo desconhecido mantém o firewall anterior), `Reload`, `Stop`, `IsRunning`, `Enable/DisableInterception`, `CleanRules`, `SaveConfiguration`, `ErrorsChan`/`ErrChanEmpty`, `Serialize`, `Deserialize`. `ReloadSystemRules` não tem quem a chame no upstream e não foi portada |
| `daemon/firewall/nftables/{nftables,tables,chains,rules,monitor,utils}.go` | `daemon/fw/nft.c`, `daemon/fw/nft_priv.h` | portado | interceptação (tabela, cadeias, as 3 regras, limpeza por chave, `AreRulesLoaded`, `ReloadRulesCallback`), `Serialize`/`Deserialize`, e as partes de sistema: `InsertRule`, cadeias regulares, backup e restauração das policies (`nft_sys.c`) |
| `daemon/firewall/nftables/system.go`, `monitor.go` (`ReloadConfCallback`, `PreloadConfCallback`), `utils.go` (`GetHook`, `GetChainPriority`, `GetConntrackPriority`) | `daemon/fw/nft_sys.c` | portado | `CreateSystemRule`, `AddSystemRules` (com os UUIDs que faltam), `DeleteSystemRules`, `AddSystemRule` |
| `daemon/firewall/nftables/parser.go`, `rule_helpers.go`, `exprs/*.go` | `daemon/fw/nft_exprs.c` | portado | todas as declarações (ct, meta, ether, iifname/oifname, ip/ip6, icmp/icmpv6, log, limit, tcp/udp/udplite/sctp/dccp, quota, notrack, counter) e veredictos (accept, drop, stop, reject, return, jump, queue, snat, dnat, masquerade, redirect, tproxy), com os conjuntos anônimos e os atributos netlink do google/nftables v0.2.0 (conferidos no fonte); `tests/integration/sysfw.sh` compara o `nft list ruleset` com o do daemon do upstream |
| `daemon/firewall/common/common.go` | `daemon/fw/nft.c`, `daemon/fw/iptables.c`, `daemon/fw/sysfw.c` | portado | verificador de regras (`NewRulesChecker`, `StopCheckingRules`, `SetRulesCheckerInterval`), `ErrChan`/`SendError` (`ks_fw_errors`) |
| `daemon/firewall/config/config.go` | `common/sysfw.c` (tipos, `json.Unmarshal`), `daemon/fw/sysfw.c` (`NewSystemFwConfig`, `LoadDiskConfiguration`, `SaveConfiguration`, `monitorConfigWorker`) | portado | divergências 78 a 81 |
| `golang/protobuf` v1.5 `jsonpb.Marshaler` (`OrigName`, `EmitDefaults`, `Indent`) | `common/sysfw.c` (`ks_sysfw_pb_to_json`) | portado | o `system-fw.json` gravado a partir da UI é byte a byte o do upstream (`tests/integration/sysfw.sh`) |
| `daemon/firewall/iptables/{iptables,rules,system,monitor}.go` | `daemon/fw/iptables.c` | portado | roda `iptables`/`ip6tables` como o upstream; `QueueConnections` esvazia a tabela do conntrack (`ks_conntrack_flush_table`). Divergência 82 |
| `time.Duration.String` (Go stdlib) | `common/duration.c` (`ks_format_duration`) | portado | |
| `crypto/md5`, `crypto/sha1` (Go stdlib) | `common/hash.c` | portado | sem OpenSSL |
| `proto/ui.proto` | `proto/ui.proto`, `common/pb/` | copiado | `tools/sync-proto.sh` copia e regenera `common/pb/` (protoc-c 1.3.3; o código gerado roda com libprotobuf-c 1.3 ou mais nova) |
| `daemon/data/default-config.json`, `network_aliases.json`, `daemon/ui/testdata/*.json`, `daemon/rule/testdata/` | `tests/fixtures/upstream/` | copiado | `tools/sync-fixtures.sh` |
| `ui/bin/opensnitch-ui` | `ui/main.c`, `ui/server.c` | portado | argumentos (`--socket`, `--socket-auth` (TLS com `TLS=1`), `--tls-ca-cert`, `--tls-cert`, `--tls-key`, `--max-clients`; `--max-workers` aceito e ignorado; `--background`, `--debug`), instância única no mesmo socket do `QLocalServer`, `create_socket_dirs`, endereço de `global/server_address`, opções do servidor (keepalive 5 s / 20 s, `getMaxMsgLength`), `restrict_socket_perms`. TLS com `TLS=1` (fase 10). Fora, justificado: temas e escala do Qt (não se aplicam ao GTK) |
| `ui/opensnitch/service.py` (`UIService`) | `ui/service.c`, `ui/tray.c`, `ui/main.c` | portado | `Subscribe` (com `_overwrite_nodes_config`), `Notifications`, `Ping` (aviso de versão), `AskRule` (uma pergunta por vez, mensagem de timeout, `ADD_RULE`/`DELETE_RULE` na tabela de regras, regra temporária desativada ao expirar), `PostAlert` (a mensagem), estado da bandeja (`_set_daemon_connected`, `_update_fw_status`, `_enable_interception`), menu, `_on_close`. Estatísticas, nós e alertas no banco: `ui/statsdb.c`. Janela principal: `ui/stats_win.c`; traduções (`_init_translation`): `ui/i18n.c`, no `ui/main.c`. Fora, justificado: o mecanismo de plugins (a fase 10 do `docs/PORTING.md` não o lista; só o plugin `highlight` existe, em `ui/highlight.c`) |
| `ui/opensnitch/notifications.py` (`DesktopNotifications`) | `ui/notify.c`, `ui/main.c` (`on_message`) | portado | libnotify no lugar do notify2, só com `NOTIFY=1`: `show` (urgência pela prioridade do alerta, categoria `network`, botão "Open" que abre a janela de estatísticas se o daemon de notificações suporta ações). `ask()` não tem uso no upstream. Divergência 99 |
| `ui/opensnitch/nodes.py` | `ui/nodes.c` | portado | `add`, `get_node`, `delete`, `count`, `get_addr`, `get_client_config`, `get_node_hostname`, fila de notificações, `send_notification(s)`, `reply_notification`, `start_interception`/`stop_interception`. Tabela de nós: `ui/statsdb.c` (`insert`, `update`, `update_all`, `reset_status`). `reload_fw` (`ks_nodes_reload_fw`), `add_fw_config` (o `system-fw.json` editável do nó em `node->fw`). `change_node_config`: o `CHANGE_CONFIG` de `ui/prefs.c` e `ui/fw_dialog.c`; importar/exportar regras: `ui/rulesops.c` |
| `ui/opensnitch/rules.py`, `ui/opensnitch/database/__init__.py` (tabela `rules`) | `ui/rulesdb.c`, `ui/db.c` | portado | linhas em memória com gravação imediata na tabela `rules` do SQLite (`ks_rulesdb_attach`), mesmas colunas e valores: `add`, `add_rules` (lista como `MessageToJson`), `exists`, `new_unique_name`, `get_by_field` (com o `LIKE` do SQLite), `disable`, `delete`, `delete_by_field`, `Rule.new_from_records`. `update_time` (`ks_rulesdb_update_time`), exportar/importar: `ui/rulesops.c` |
| `ui/opensnitch/service.py` (`_populate_stats*`, `_on_new_alert`), `ui/opensnitch/nodes.py` (`insert`, `update`, `update_all`, `reset_status`) | `ui/statsdb.c` | portado | nós, eventos (`INSERT OR IGNORE`: a restrição `UNIQUE` não inclui o horário), contadores `hosts`/`procs`/`addrs`/`ports`/`users` (`INSERT OR REPLACE`, só o que mudou desde o `Ping` anterior), horário da regra que casou, alertas. O aviso à janela de estatísticas vem com ela |
| `ui/opensnitch/database/__init__.py`, `database/migrations/` | `ui/db.c` | portado | `initialize` (quick_check, `user_version`, modo do journal, `PRAGMA synchronous`), `_create_tables` (inclusive o índice `sck_dsthost_index` que o upstream não consegue criar), `_upgrade_db_schema` (migrações 1 a 3 embutidas), `close`, `clean`, `vacuum`, `optimize`, `purge_oldest`, `get_oldest_record`/`get_newest_record`, `empty_rule`, `delete_alert`, `get_total_records`. As consultas das abas: `ui/statsq.c`; os INSERT/UPDATE das tabelas: `ui/statsdb.c`. Fora, justificado: `insert`/`update`/`insert_batch` genéricos (helpers do Python para montar SQL; o port escreve o SQL de cada tabela) |
| `ui/opensnitch/dialogs/stats.py` (consultas: `_set_events_query`, `_set_nodes_query`, `_set_rules_query`, `_set_hosts_query`, `_set_process_query`, `_set_addrs_query`, `_set_ports_query`, `_set_users_query`, `_set_rules_filter`, `_get_filter_line_clause`, `_get_nodes_filter_query`, `_get_indetail_filter_query`) | `ui/statsq.c` | portado | `TABLES[...]['display_fields']`, ordenação e `LIMITS` incluídos; testado contra um banco real (`tests/unit/test_ui_statsq.c`) |
| `ui/opensnitch/customwidgets/generictableview.py` (`GenericTableModel`, `GenericTableView`: consulta, contagem de linhas, só o visível é lido) | `ui/qmodel.c`, `ui/qstore.c` | portado | `GtkTreeModel` virtual (`LIMIT/OFFSET` com uma página em cache) e `GtkTreeView` em modo de altura fixa; 100 mil eventos: 32 ms para consultar, 7 ms para cinco telas (`tests/unit/test_ui_qmodel.c`), 0,5 s para abrir a janela e 46 MB de RSS (`tests/integration/stats_win.sh`) |
| `ui/opensnitch/rules.py` (`rule_to_json`, `export_rule`, `export_rules`, `import_rules`, `_timestamp_to_rfc3339`), `dialogs/stats.py` (`_table_menu_change_rule_field`, `_table_menu_enable`, `_table_menu_duplicate`, `_table_menu_apply_to_node`, `_del_rule`), `nodes.py` (`delete_rule`, `import_rules`) | `ui/rulesops.c` | portado | tabela e notificação (`CHANGE_RULE`, `ENABLE_RULE`, `DISABLE_RULE`, `DELETE_RULE`) como no upstream; o JSON exportado é o `MessageToJson` + `json.dumps(indent=4)` do original (conferido contra o `protobuf` de Python) |
| `dialogs/stats.py` (`_update_node_info`, formatação de uptime e bytes) | `ui/nodeinfo.c` | portado | com as esquisitices (todo valor acima de 0 sai em KB ou mais; uptime sempre na forma de dias, com os dias arredondados); expectativas conferidas com a aritmética do Python |
| `csv.writer` (`_copy_selected_rows`) | `ui/pycsv.c` | portado | `QUOTE_MINIMAL`, linhas terminadas em `\r\n` |
| `ui/opensnitch/dialogs/ruleseditor.py`, `res/ruleseditor.ui` | `ui/rules_editor.c` (GTK), `ui/rulegen.c` (lógica) | portado | todos os campos: processo, linha de comando, usuário, PID, protocolo, interface, portas, IPs e redes (com os apelidos e `LAN`/`MULTICAST`), host, as quatro listas, md5, sensível, sem log, prioridade, ação, duração, nó e \"aplicar a todos\"; regras simples, de lista e compostas; criar, criar a partir de um evento, editar e renomear. `make diff-ui` (`tests/diff/ruleseditor/`) roda 850 casos (formulário para regra, regra para formulário, auxiliares) pelo próprio código do upstream e pelo nosso: resultados idênticos. O \"Enable\" nasce desmarcado, como no `.ui` do upstream |
| `ui/opensnitch/dialogs/preferences.py`, `res/preferences.ui` | `ui/prefs.c` (GTK), `ui/prefs_node.c` (configuração do nó) | portado | abas Pop-ups, UI, Rules, Nodes e Database; o JSON de configuração do nó (carregar e montar) passa por `make diff-ui` (`tests/diff/prefs/`, 719 casos idênticos ao código do upstream). Fica de fora (só Qt): tema, escala de tela, plataforma Qt; idioma espera a fase 10; o teste de notificações mostra uma com `NOTIFY=1` |
| `ui/opensnitch/dialogs/processdetails.py`, `res/process_details.ui` | `ui/stats_proc.c`, `ui/procinfo.c` | portado | o JSON de `procmon.Process`, os rótulos, as seis abas e os filtros de arquivos e sockets; o texto sai da mesma formatação do Python (`tests/unit/test_ui_procinfo.c`); a aba mostrada é preenchida também ao trocar de aba (o upstream espera o próximo envio) |
| `dialogs/stats.py` (`_update_netstat_table`, `_monitor_node_netstat`, `_unmonitor_node_netstat`), `utils/sockets.py`, `customwidgets/netstattablemodel.py` | `ui/stats_netstat.c`, `ui/netstat.c` | portado | com o JSON de `daemon/tasks/socketsmonitor`; o nosso daemon ainda responde \"not supported yet\" às tarefas (fase 10) |
| `actions/default_configs.py`, `plugins/highlight/highlight.py`, `customwidgets/colorizeddelegate.py` | `ui/highlight.c` | parcial | as quatro configurações padrão e o casamento de \"cells\"; fora, justificado: as configurações do usuário em `~/.config/opensnitch/actions/` e os \"rows\" são do mecanismo de plugins, que a fase 10 do `docs/PORTING.md` não lista |
| `ui/opensnitch/dialogs/stats.py`, `res/stats.ui` (janela), `dialogs/conndetails.py`, `utils/infowindow.py` | `ui/stats_win.c`, `ui/stats_menu.c`, `ui/stats_node.c`, `ui/stats_win_priv.h` | portado | abas Events, Nodes, Rules, Hosts, Applications, Addresses, Ports, Users; filtro, combo de ação, limite, contagem de linhas, ordenação por coluna, detalhe por duplo clique e botão de voltar, limpar, contadores do `Ping`, início/parada da interceptação, coluna do nó escondida com menos de dois nós; menu de contexto dos eventos (detalhes) e das regras (aplicar a outro nó, ação, duração, ativar/desativar, duplicar, apagar, exportar para a área de transferência e para o disco) e dos alertas (ver, apagar, exportar); Ctrl+C (CSV) e Del como no upstream (só a tabela de eventos tem os dois atalhos, e Del não faz nada nela); painel do nó (tarefa `node-monitor`), botões do detalhe do nó (interceptação, apagar, exportar e importar regras); aba Netstat (tarefa `sockets-monitor`, tabela `sockets`, combos de intervalo, nó, protocolo, família e estado), informação dos alertas por duplo clique, diálogo de detalhes do processo (duplo clique no PID, botão \"Process details\" da aba Applications; tarefa `pid-monitor`), cores das células (as configurações padrão do plugin `highlight`), `show_columns`; ícone da bandeja e pedido de outra instância abrem a janela; última aba, filtro, ação e limite lembrados. Botão "Actions" (exportar e importar regras de todos os nós, exportar a aba para CSV, sair), "Help" (diálogo em vez de tooltip) e intervalo de atualização (`statsDialog/refresh_interval`). "Edit"/"New" abrem o editor de regras e o botão de preferências, o diálogo de preferências. Firewall de sistema: `ui/stats_fw.c` (abaixo). `docs/UI-CHECKLIST.md` lista cada widget dos `.ui` |
| `ui/opensnitch/firewall/` (`__init__.py`, `rules.py`, `chains.py`, `exprs.py`, `enums.py`, `profiles.py`), `utils.NetworkServices` | `ui/fwrules.c` | portado | regras (add, insert, update, delete, swap, is_duplicated, enable, change_rule_field, to_array, filter_rules), `get_policy`, perfis (`apply_profile`, `delete_profile`); `load_predefined_profiles` não (o combo de perfis fica escondido, como no upstream). Divergências 83 e 84 |
| `ui/opensnitch/dialogs/firewall.py`, `res/firewall.ui` | `ui/fw_dialog.c` | portado | políticas de entrada e saída (perfis), ligar/desligar (as duas notificações com 500 ms de intervalo, sem bloquear a UI), troca de iptables para nftables, configuração desatualizada, "Allow service", nova regra, ajuda |
| `ui/opensnitch/dialogs/firewall_rule.py`, `res/firewall_rule.ui` | `ui/fw_rule_dialog.c` (GTK), `ui/fwrules.c` (`ks_fwf_*`: formulário para regra, regra para formulário, títulos, opções) | portado | todas as condições, direções e ações; nova regra, editar, apagar, "Exclude service"; respostas do daemon como no upstream. Condições em expanders (divergência 85) |
| `dialogs/stats.py` (partes do firewall: `fwButton`, `_configure_fwrules_contextual_menu`, `_table_menu_*` do `fwTable`, `_cb_fw_table_rows_reordered`), `customwidgets/firewalltableview.py` | `ui/stats_fw.c` | portado | item "Firewall" do combo de regras (divergência 66), colunas do `FirewallTableModel`, filtro de texto, duplo clique edita, menu (ação, ativar/desativar, apagar, editar, exportar para a área de transferência), botões de subir/descer no lugar do `UpDownButtonDelegate` |
| `ui/opensnitch/config.py` | `ui/settings.c` | portado | chaves, valores gravados no primeiro uso, `getBool`/`getInt`/`getSettings`, `reload`; `setRulesDurationFilter` em `ui/rulesdb.c`, `getMaxMsgLength` em `ui/server.c`. O arquivo é lido e gravado no formato INI do `QSettings` (`qsettings.cpp`: `iniEscapedKey`, `iniEscapedString`, `iniUnescapedStringList`), preservando o que não é nosso |
| `ui/i18n/locales/*/opensnitch-*.ts` (Qt Linguist), `ui/i18n/Makefile`, `generate_i18n.sh` | `po/*.po`, `po/kisnitch.pot` (`tools/ts2po.py`, `tools/update-po.sh`), `build/locale/*/LC_MESSAGES/kisnitch.mo` (`msgfmt`) | portado | o texto em inglês é o msgid, como no `tr()` do Qt; os `.po` são gerados dos `.ts` do submódulo e não se editam à mão. Divergência 102 |
| `ui/opensnitch/utils/languages.py` (`init`, `save`, `get_all`), `service.py` (`_init_translation`), `dialogs/preferences.py` (`_load_langs` e o salvamento do idioma) | `ui/i18n.c`, `ui/main.c`, `ui/prefs.c` | portado | `global/language` (vazio: o do sistema; `en`: sem tradução) e `global/langname`; trocar o idioma pede reinício ("Language changed"). O combo lista os catálogos instalados em `$(DATADIR)/locale`; `zh_Hans` do original é lido como `zh_CN` |
| `ui/opensnitch/dialogs/prompt/__init__.py`, `_utils.py`, `_constants.py`, `_details.py`, `_checksums.py`, `res/prompt.ui` | `ui/prompt.c` (GTK), `ui/prompt_rule.c` (lógica) | portado | combos, padrões, textos, contagem regressiva, ações, opções avançadas, detalhes, aviso e atualização de checksum; `make diff-ui` compara a lógica com o código Python do upstream. Plugins do popup na fase 10 |
| `ui/opensnitch/desktop_parser.py` | `ui/desktop.c` | portado | com as regras do `configparser` que ele usa; inotify |
| `ui/opensnitch/utils/network_aliases/` | `ui/prompt_rule.c` (`ks_py_aliases_*`), `ui/res/network_aliases.json` | portado | semântica do `ipaddress` do Python (diferente da do daemon: `::1` vale como `/128`) |
| `ui/opensnitch/utils/xdg.py` (`Autostart`, `get_run_opensnitch_dir`), `ui/opensnitch/utils/__init__.py` (`create_socket_dirs`, `check_versions`) | `ui/tray.c`, `ui/main.c`, `ui/service.c` | portado | |
| `ui/opensnitch/utils/duration/duration.py` | `ui/service.c` (`ks_ui_duration_seconds`) | portado | |
| `python-slugify` (`slugify`) | `ui/slug.c`, `ui/slug_tables.h` | portado | tabelas geradas por `tools/gen-slug-tables.py` (divergência 48) |
| `json.dumps` (Python stdlib) | `ui/pyjson.c` | portado | divergência 49 |
| `grpcio` (servidor) | `common/grpc/grpc.c`, `ui/server.c` | portado | só o que o protocolo usa; ver `docs/PROTOCOL.md` |
| `ui/opensnitch/res/icon-*.png`, `ui/opensnitch/utils/network_aliases/network_aliases.json` | `ui/res/` | copiado | `tools/sync-ui-res.sh`; embutidos no binário por `tools/bin2c.c` |

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
| 24 | `daemon/main.c`, `daemon/queue.c` | 16 workers; se nenhum pega o pacote em 1 ms, ele é aceito sem avaliação (marca 0) | cada pacote é avaliado no loop, em ordem; nunca aceito sem avaliação | arquitetura de um loop (seção 4 do PORTING.md); o upstream abre a rede sob carga |
| 25 | `daemon/fw/nft.c` | `MonitorInterval` negativo derruba o daemon (`time.NewTicker` entra em pânico) | o verificador é desligado, com aviso | não derrubar o daemon por config |
| 26 | `daemon/main.c` | se a fila não pode ser criada, `log.Fatal` sai com as regras de interceptação instaladas (sem `QueueBypass`, a rede fica bloqueada) | as regras são removidas antes de sair | não deixar a máquina sem rede por um erro de inicialização |
| 27 | `daemon/queue.c` | `go_callback` indexaria um payload vazio (pânico) | pacote sem payload é aceito | o kernel não manda pacote vazio; defensivo |
| 28 | `daemon/fw/nft.c` | mensagens de regra com `NLM_F_ECHO`; `ReloadRulesCallback` dorme 500 ms na goroutine do verificador | sem eco; os 500 ms são um timer do loop | não muda o estado do kernel; o loop não pode bloquear |
| 29 | `daemon/fw/nft.c` | listas de cadeias e regras com o buffer do google/nftables | respostas lidas com buffer de 64 KiB, e respostas pendentes de um dump interrompido são descartadas antes da próxima operação | robustez; mesmo resultado |
| 31 | `daemon/dns/cache.c` | o mapa IP/CNAME → nome nunca diminui: cada IP e CNAME distinto visto fica até o daemon parar | guarda as 8192 entradas usadas mais recentemente (consultar ou gravar conta como uso); a mais antiga sai | memória limitada (cheio, cerca de 2 MB; `docs/BENCH.md`). A conexão vem logo depois da resolução, então a entrada que importa é sempre recente |
| 32 | `daemon/dns/parse.c` | percorre os nomes da mensagem sem limite: cadeias de ponteiros de compressão compartilhadas por milhares de registros custam dezenas de MB de cópia por pacote | no máximo 4 MiB de rótulos percorridos por mensagem (`KS_DNS_WORK_MAX`); acima disso a mensagem é rejeitada (sem camada DNS) | o parser roda como root sobre pacotes da rede; respostas reais ficam ordens de grandeza abaixo (teste `work_is_bounded`) |
| 33 | `daemon/dns/cache.c` | nomes com bytes NUL (rótulos DNS aceitam qualquer byte) são guardados e comparados inteiros | respostas e perguntas com NUL no nome são ignoradas (não entram no cache nem viram `DstHost`) | strings C; truncar no NUL faria `a.com\0x` casar com regras de `a.com` |
| 34 | `daemon/dns/resolved.c` | após perder a conexão com o systemd-resolved, `connPoller` tenta reconectar uma vez (em até 5 s); se falhar, ou se a nova inscrição falhar, o monitor fica desligado até reiniciar o daemon | tenta a cada 5 s até conseguir | o resolved reinicia em atualizações de pacote; o upstream perde o monitor se ele demorar |
| 35 | `daemon/dns/resolved.c` | mensagens varlink de qualquer tamanho | até 4 MiB; acima disso desconecta e reconecta | proteção de memória; as respostas do monitor têm poucos KB |
| 36 | `daemon/dns/resolved.c` | as linhas de log de resposta sem sucesso e de trace imprimem a struct com `%v`/`%#v` | imprimem estado e número de respostas | formato de struct do Go; só log |
| 37 | `daemon/intercept.c`, `daemon/main.c` | para perguntar à UI, o pacote é reenfileirado na fila `N+1` (`SetRequeueVerdict`) e lido de volta em até 1 s; a goroutine fica bloqueada na resposta | o veredicto do pacote fica pendente pelo id e sai quando a UI responde; não há fila `N+1` | loop único (seção 4 do PORTING.md); o efeito para o resto do tráfego é o mesmo, e a fila `N+1` deixa de ser ocupada |
| 38 | `daemon/uiclient.c` | `PostAlert` com compressão gzip | sem compressão | evita a zlib; a UI aceita os dois |
| 39 | `daemon/uiclient.c`, `common/grpc/tls.c` | `Server.Authentication.Type` `tls-simple`/`tls-mutual` conecta com TLS (sempre disponível) | com `TLS=1`, igual; sem, não conecta e avisa a cada segundo ("Invalid client auth options: TLS is not supported by this build (TLS=1)"). Num socket unix, o nome verificado é o caminho (o grpc-go usa o alvo como autoridade): só passa com `SkipVerify`, como no upstream | OpenSSL é opcional |
| 41 | `daemon/uiclient.c`, `daemon/tasks/` | as asserções de tipo dos dados das tarefas (`conf["pid"].(string)`, `conf["node"]`, `conf["interval"]` do `node-monitor`, os campos do `sockets-monitor`, o `interval` do `looper` e do `IOC-scanner` lidos do disco, `opts.Cmd[0]` de uma ferramenta sem comando, `path[1]` nas linhas de uma coluna do debsums) e o `SetID` no `sockets-monitor` nulo (configuração que não é objeto) derrubam o daemon | responde erro com o texto do pânico (`interface conversion: interface {} is nil, not string`) ou `[sockmon] invalid config received: <JSON>` | não derrubar o daemon por mensagem da rede |
| 42 | `daemon/uiclient.c` | `ENABLE_RULE`/`DISABLE_RULE` com regra sem operador derruba o daemon (ponteiro nulo) | responde erro | não derrubar o daemon por mensagem da rede |
| 43 | `daemon/uiclient.c` | `unix-abstract:<nome>` disca a rede `unix-abstract`, que o Go não conhece: nunca conecta | conecta no socket abstrato `<nome>` | é o que o endereço quer dizer (a UI converte `unix:@nome` para `unix-abstract:nome` achando que o daemon entende) |
| 44 | `daemon/stats.c` | `Statistics.daemon_version` é a versão do daemon | é a versão do upstream (`1.8.0`) | a UI espera `x.y.z` (`Utils.check_versions`); com a versão do port ela descartaria as estatísticas |
| 45 | `daemon/stats.c` | se `Stats.MaxEvents` diminui em execução abaixo do número de eventos guardados, o teste `==` nunca mais dispara e a lista cresce sem limite | descarta os mais antigos até caber | memória limitada |
| 46 | `daemon/protocol.c` | `Rule.Serialize()` de regra `list` também apaga `Operator.Data` da regra carregada em memória | só a mensagem vai com `data` vazio | a regra em memória não é gravada de novo a partir daí; mesmo resultado na rede |
| 47 | `daemon/uiclient.c` | cada evento do fsnotify no arquivo de config recarrega o arquivo | vários eventos lidos de uma vez recarregam uma vez | a segunda recarga do upstream compara com o config já atualizado e não muda nada |
| 48 | `ui/slug.c` | `slugify` translitera qualquer caractere com o `unidecode` (CJK vira pinyin, etc.) | tabelas geradas cobrem latim, grego, cirílico, pontuação geral, sobrescritos, moedas, símbolos de letra, formas numéricas, ligaturas e formas largas; fora delas o caractere vira separador | a tabela inteira do unidecode tem megabytes; só o nome da regra muda, e só para caminhos com esses caracteres |
| 49 | `ui/pyjson.c` | `json.dumps` escreve inteiros de qualquer tamanho e floats como `1.0` | inteiros até 1e16 sem `.0`; acima disso, como float | o cJSON não guarda o literal; só afeta o config devolvido no `Subscribe`, do qual o daemon só lê `DefaultAction` |
| 50 | `ui/settings.c` | o `QSettings` ordena grupos e chaves ao gravar e trava o arquivo (`QLockFile`) | mantém a ordem do arquivo, chave nova no fim do grupo; sem trava, gravação atômica (arquivo temporário + `rename`) | os dois leem o mesmo conteúdo; a UI só grava padrões ausentes |
| 51 | `ui/prompt.c` | `saveGeometry()` grava `promptDialog/geometry` a cada resposta | não grava | é o formato binário do Qt; não serve ao GTK |
| 52 | `ui/service.c` | perguntas que chegam com outra na tela esperam o lock; se o daemon desiste (prazo de 120 s), o popup aparece mesmo assim e a resposta se perde | pergunta na fila cujo daemon desistiu é descartada sem aparecer; a que já está na tela continua, como no upstream | não mostrar popup de conexão já decidida |
| 53 | `ui/prompt_rule.c` | `whatCombo` sem seleção (`default_target` fora da faixa) ou caminho de snap com menos de 3 partes: exceção no `_send_rule`, que devolve uma regra pela metade (`user.choice`, operador vazio) | nenhuma regra: o daemon recebe erro e aplica a ação padrão | regra inválida |
| 54 | `ui/prompt.c`, `ui/prompt_rule.c` | rótulos em rich text do Qt: nome de processo ou host com `<` vira marcação | marcação Pango com escape | sem injeção de marcação |
| 55 | `ui/prompt_rule.c` | `str.isprintable()` (categorias Unicode) filtra rótulos | filtra controles C0/C1, separadores e caracteres de formatação conhecidos | basta para os rótulos; não afeta regras |
| 56 | `ui/service.c`, `ui/main.c` | mensagens na bandeja ou notificações de desktop (`show_systray_msg`) | vão para o log, e o ícone da bandeja muda para o de alerta | o `GtkStatusIcon` não tem balão; notificações de desktop na fase 10 (`NOTIFY=1`) |
| 57 | `ui/tray.c` | "Open main window" e o clique no ícone abrem a janela de estatísticas | entrada desabilitada; o clique limpa o alerta | janela principal na fase 7 |
| 58 | `ui/desktop.c` | ícone padrão `res/terminal.svg` | ícone de tema `utilities-terminal` | mesmo significado, sem arquivo extra |
| 59 | `ui/main.c` | `--socket-auth`/`auth/type` `tls-simple` e `tls-mutual` servem com TLS | com `TLS=1`, igual; sem, a UI não sobe ("Invalid TLS credentials ... TLS is not supported by this build") | OpenSSL é opcional |
| 60 | `ui/nodes.c` | id de notificação `int(str(time.time()).replace(".", ""))` pode repetir | o mesmo cálculo, forçado a crescer | ids únicos |
| 61 | `ui/db.c` | o banco em memória é `file::memory:` com cache compartilhado (o `QSqlDatabase` clona a conexão para a janela de nós remotos) | `:memory:` privado de uma conexão só | uma conexão só; a janela de nós remotos virá com a janela de estatísticas e, se precisar, reabre o assunto |
| 62 | `docs/PORTING.md` (fase 7) | o plano pedia "limpeza por limite de eventos" | limpeza por dias (`database/max_days`, `purge_oldest`), como o upstream | o upstream não limita por contagem; não inventamos comportamento |
| 63 | `ui/statsdb.c` | `Nodes.insert` grava em `daemon_uptime` o `datetime` de `last_seen` (o Qt converte como quiser) | `"%Y-%m-%d %H:%M:%S.%f"` | o primeiro `Ping` sobrescreve o campo com o uptime do daemon |
| 64 | `ui/statsq.c` | os filtros e os valores de detalhe entram no SQL por interpolação (`LIKE '%{0}%'`, `c.dst_host = '{14}'`): uma aspa simples no filtro quebra a consulta | as aspas simples são dobradas; `%` e `_` continuam sendo curinga | uma aspa no texto de busca não pode derrubar a aba nem injetar SQL |
| 65 | `ui/stats_win.c`, `ui/qstore.c` | `QTableView` com barra de rolagem própria, número da linha no cabeçalho vertical, seleção guardada por valor da coluna de rastreamento e restaurada a cada atualização | `GtkTreeView` em modo de altura fixa sobre um modelo virtual, sem cabeçalho vertical; ao atualizar a tabela volta à primeira linha visível, mas a seleção se perde | o GTK 2 não tem o equivalente; a atualização só acontece se não houver linhas selecionadas, como no upstream |
| 66 | `ui/stats_win.c` | a aba Addresses tem a coluna "Network name" (ASN) quando o `pyasn` está disponível; a aba Rules tem uma árvore (aplicações, alertas, nós, firewall) | sem coluna de ASN; um combo (todas, permanentes, temporárias, alertas, e um item por nó, sem o firewall até a fase 8) | o banco de ASN é uma dependência do Python; o combo é o que o próprio upstream mostra quando a árvore está recolhida |
| 67 | `ui/stats_node.c` | a resposta de erro de `node-monitor` não aparece (só a de `sockets-monitor` vai para o rótulo do netstat); sem resposta o painel fica em "loading node information..." | o texto do erro do daemon aparece no painel | saber por que o painel não carrega |
| 68 | `ui/stats_win.c` | `_del_by_field` na aba Users compara `uid` com "name (uid)": o botão de limpar apaga a linha de `users` e nenhum evento | extrai o uid do texto, então apaga também os eventos | bug do upstream |
| 69 | `ui/stats_menu.c`, `ui/stats_node.c` | "Edit" e "New" abrem o editor de regras; o botão de preferências do nó abre a janela de preferências | desabilitados, com dica | o editor de regras e as preferências são os próximos passos da fase 7 |
| 70 | `ui/stats_node.c` | um clique no nó guarda o endereço em `LAST_SELECTED_ITEM` mesmo ao sair da aba (o próximo clique no mesmo nó "desmonitora" de novo); o painel fica em um splitter que o usuário abre | sair da aba envia `TASK_STOP` e esquece o nó; o painel aparece ao selecionar o nó e some ao desmarcar | estado coerente; sem arrastar o splitter |
| 71 | `ui/tray.c`, `data/kisnitch.desktop` | o autostart usa `opensnitch_ui.desktop` (copiado de `/usr/share/applications`, com `Exec=opensnitch-ui`) | usa `kisnitch.desktop`, instalado por `make install-data` com `Exec=kisnitch-gtk` | com o nome do upstream, o autostart ligado pela nossa UI abriria a UI original |
| 72 | `data/` | ícone `opensnitch-ui` e `io.github.evilsocket.opensnitch.appdata.xml` | ícone próprio `kisnitch` (SVG em `data/icons/`, PNGs de `tools/gen-icons.sh`) e `io.github.kisnitch.metainfo.xml` | identidade do projeto; os ícones da bandeja continuam sendo os do upstream (`ui/res/`) |
| 73 | `ui/rulegen.c` | `_is_valid_regex` compila com o `re` do Python | PCRE2, com um filtro que recusa o que o `re` recusa e o PCRE2 aceita (escapes de letra ASCII desconhecidos como `\\p`, `\\h`, `\\z`, `(?<nome>`, `(?|`, `(?'nome'`) e aceita o que o `re` aceita e o PCRE2 não (`\\N{NOME}`, repetições acima de 65535) | o Python não está linkado; os 850 casos do teste diferencial coincidem. Flags globais no meio do padrão (`a(?i)b`): erro no Python 3.11 ou mais novo (só aviso no 3.10), e seguimos o 3.11; o teste diferencial só inclui o caso a partir do 3.11. Os quantificadores possessivos (`a*+`) o Python aceita só a partir da 3.11; aceitamos |
| 74 | `ui/prefs.c` | autenticação TLS do servidor da UI pode ser salva | com `TLS=1`, igual; sem, ao salvar com tipo diferente de Simple mostra "TLS is not supported by this build (TLS=1)" e mantém Simple | a UI sem TLS não subiria (divergência 59) |
| 75 | `ui/service.c` | o limpador do banco (`purge_oldest`) roda em timer da janela Qt | timer GLib de `database/purge_interval` minutos que chama `ks_db_purge_oldest(max_days)`; reiniciado ao salvar as preferências | mesmo efeito, sem Qt |
| 76 | `ui/stats_win.c` | `_needs_refresh` compara com `datetime.now()` | compara com relógio monotônico | imune a mudança de hora |
| 77 | `daemon/config.c`, `daemon/rules/loader.c`, `ui/settings.c` | grava o arquivo no lugar (`os.WriteFile`, `QSettings`) | grava em `<arquivo>.tmp` com fsync e `rename`, copia o arquivo anterior para `<arquivo>.backup` (só se íntegro) e, ao ler, usa o `.backup` se o arquivo faltar ou estiver vazio/zerado/inválido (`ks_write_file_safe`, `ks_read_file_or_backup`) | sobrevive a queda de energia; apagar um arquivo para "resetar" exige apagar o `.backup` também (apagar uma regra pela UI apaga o dela) |
| 78 | `common/sysfw.c` | `json.Unmarshal` no `SysConfig` já carregado: campos ausentes no arquivo novo mantêm o valor antigo; um elemento `null` numa lista vira ponteiro nulo (e pânico mais adiante, ex.: `Statement` nulo em `parseExpression`) | o arquivo é decodificado do zero; `null` numa lista é um elemento vazio, e uma expressão sem `Statement` é inválida (erro no canal de erros) | arquivos gravados pela UI têm todos os campos; não derrubar o daemon |
| 79 | `daemon/fw/sysfw.c` | `LoadDiskConfiguration` só passa a vigiar o arquivo se ele for lido e decodificado (um arquivo malformado na partida nunca é recarregado, embora o comentário diga o contrário) | vigia mesmo com erro de decodificação | o comentário do upstream diz que é essa a intenção |
| 80 | `daemon/fw/sysfw.c` | `SaveConfiguration` grava o arquivo no lugar (o fsnotify pode recarregar o arquivo truncado e vazio) | grava como os outros arquivos (divergência 77: `.tmp`, `rename`, `.backup`), modo 0600 | recarga sem estado intermediário vazio |
| 81 | `daemon/uiclient.c` | a resposta do `RELOAD_FW_RULES` sai de uma goroutine que espera os erros no canal ou 2 s | um timer de 50 ms consulta a fila de erros até 2 s | mesmo resultado no loop único |
| 82 | `daemon/fw/iptables.c`, `daemon/fw/nft_exprs.c` | `log.Fatal` (sai do daemon) se a regra de fila do iptables falhar; pânico com `iifname` sem valores, MAC com byte de tamanho ímpar ou vazio, IP de NAT IPv6 com `:` | erro no log e a regra não é aplicada | não derrubar o daemon |
| 83 | `ui/fwrules.c` | `form_to_protobuf` altera o `STATM_CONF` da classe (`sk['key'] = ...`): depois de uma condição "meta", uma porta tcp+udp sai como `meta <opção anterior>` em vez de `meta l4proto` | as chaves não mudam entre chamadas | bug do upstream (a relatar) |
| 84 | `ui/fwrules.c` | `ipaddress.ip_network()` monta a lista de todos os endereços da rede (trava com redes IPv6 grandes); erros de `int()` na cota viram exceção não tratada | calcula o primeiro e o último endereço; a mensagem do `ValueError` vira erro do formulário | mesmo resultado sem travar |
| 85 | `ui/fw_rule_dialog.c` | ao carregar uma regra de porta tcp+udp, a escolha do serviço no combo troca o protocolo para tcp (o `currentIndexChanged` não está bloqueado), e salvar a regra a muda | o protocolo carregado fica; o QToolBox vira uma coluna de expanders, um aberto por vez | o diálogo não deve alterar a regra que só foi aberta |
| 86 | `daemon/tasks/pidmon.c`, `sockmon.c` | `pidmonitor.New` ignora `stopOnDisconnect` e o `socketsmonitor` o grava num campo que sombreia o do `TaskBase`: só o `node-monitor` é temporário. Ao desconectar, as outras duas seguem mandando ao stream fechado, e depois de reconectar um novo start falha com "already exists" | as três tarefas da UI são temporárias e param ao desconectar | é o que o argumento `true` pede |
| 87 | `daemon/tasks/tasks.c` | intervalo zero ou negativo: `time.NewTicker` entra em pânico | erro no start (só log, a tarefa fica parada), como um intervalo inválido | não derrubar o daemon |
| 88 | `daemon/uiclient.c` | o resultado de cada tarefa vai ao stream de notificações que existia quando ela começou | vai ao stream atual (as tarefas da UI param ao desconectar, divergência 86) | mesmo efeito |
| 89 | `daemon/tasks/sockmon.c` | uma goroutine por socket: a ordem de `Table` varia a cada chamada | a ordem do dump (lista de opções do upstream, depois XDP, depois AF_PACKET) | determinístico; a UI ordena a tabela |
| 90 | `daemon/tasks/load.c` | cada evento de escrita ou renomeação de um arquivo de tarefas espera 1 s e recarrega (vários eventos, várias recargas) | uma recarga por arquivo a cada espera de 1 s | mesmo efeito |
| 91 | `daemon/tasks/iocscanner.c`, `downloader.c` | um erro de tipo na configuração da tarefa (`json.Unmarshal`) só gera aviso, e a tarefa segue com o que foi decodificado antes do erro | aviso e configuração vazia (o IOC-scanner fica sem ferramentas e não inicia) | o decodificador de `common/json_schema.c` não guarda decodificação parcial |
| 92 | `daemon/tasks/iocscanner.c` | ao fim da primeira execução, `Stop()` cancela o contexto da ferramenta e fecha o relatório: as execuções seguintes não iniciam o comando (só mandam cabeçalho e rodapé), não gravam relatório, e o yara perde a lista de varredura. A saída inteira fica na memória | toda execução agendada roda; o arquivo de relatório (nome com a hora de criação da tarefa) recebe os relatórios em sequência e a lista do yara dura até a tarefa parar; o relatório é cortado em 64 MiB | é o que a tarefa promete (varreduras periódicas) |
| 93 | `daemon/tasks/downloader.c` | abre o arquivo da lista com `O_RDWR\|O_CREATE` sem truncar e escreve por cima: uma lista nova menor deixa o fim da antiga; o arquivo é criado (vazio) mesmo se o download falhar. Intervalo inválido: `time.NewTicker(0)` entra em pânico; tempo-limite inválido: o erro de `Start` faz o gerenciador não repassar os resultados, e a goroutine trava no primeiro envio | baixa para um temporário ao lado e renomeia se deu certo; falha não toca o arquivo. Intervalo inválido: a tarefa não inicia (log); tempo-limite inválido: sem tempo-limite, com aviso | não corromper as listas usadas pelas regras |
| 94 | `daemon/tasks/downloader.c` | `net/http` (User-Agent `Go-http-client/1.1`) | libcurl, só com `CURL=1`: redirecionamentos (até 10), gzip, proxy do ambiente e tempo-limite total como o `http.Client` | evita um cliente HTTP/TLS próprio; dependência opcional |
| 95 | `daemon/uiclient.c` | com `Tasks.ConfigPath` no arquivo de configuração, a primeira leitura (`loadDiskConfiguration`) chama `TaskMgr.LoadTaskFile` antes de o `TaskMgr` existir: pânico na partida | a lista é lida uma vez ao criar o cliente, e de novo quando o caminho muda | não derrubar o daemon |
| 96 | `daemon/loggers.c` | o logger `syslog` sem daemon de syslog (`syslog.New` falha) entra nulo no mapa de loggers e o primeiro evento derruba o daemon | erro no log e o logger é ignorado | não derrubar o daemon (contêineres e sistemas sem syslogd) |
| 97 | `daemon/loggers.c`, `daemon/logformats.c` | cada worker do gerenciador formata a mensagem ao tirá-la da fila; os checksums de `connToSD` saem na ordem aleatória do mapa | a mensagem é formatada ao entrar na fila (o carimbo de hora é o do evento); checksums em ordem de chave | determinístico; o tempo de fila é de milissegundos |
| 98 | `daemon/loggers.c` | o estado de conexão do `Remote` é um só para todos os writers (um writer reconectando marca o logger como desconectado e as mensagens são descartadas); ao reabrir após 10 erros, a conexão antiga fica aberta | o logger está conectado se algum writer estiver; a conexão antiga é fechada | sem descartes por corrida entre writers; sem vazar sockets |
| 99 | `ui/notify.c`, `ui/main.c`, `ui/prefs.c` | notificações com o nome de aplicativo `opensnitch`; tipo "Qt" mostra um balão do ícone da bandeja; com `notifications/type` de sistema gravado, a notificação aparece mesmo com `notifications/enabled` desligado | nome `kisnitch`; o GtkStatusIcon do GTK 2 não tem balões, então o tipo "Qt" é o alerta do ícone da bandeja (o ícone vira alerta em todo caso); `notifications/enabled` desligado não mostra notificações do sistema | identidade do projeto (divergência 72); GTK 2; a opção de desligar deve desligar |
| 100 | `daemon/procmon/procmon.c` | quando o audit inicia, `Init` devolve um erro do tipo `AuditdErr` (com mensagem nula); `ReconfigureMonitorMethod` trata isso como falha e volta o método para proc, com o leitor do audit ainda rodando e as regras do auditctl instaladas: o método audit nunca vale | início com sucesso não é erro: o método fica audit | é o que o método promete; com o comportamento do upstream o audit não serviria para nada |
| 101 | `daemon/procmon/audit.c` | lista de eventos sem limite (só a limpeza a cada 5 min); números de syscall de amd64 em qualquer arquitetura (o ajuste para 386 em `configureSyscalls` não muda as strings já montadas); um erro de leitura que não seja EOF vira laço sem fim | até 8192 eventos (sai o mais antigo); os números da arquitetura em que roda (os de amd64 em x86_64); qualquer erro de leitura reconecta como o EOF | memória limitada; o audit em ARM; sem laço sem fim |
| 102 | `ui/i18n.c`, `po/` | traduções do Qt (`QTranslator`, `.qm`) por contexto (a classe do widget) e com `%1`; o Qt também traduz o que é dele (botões padrão) | gettext (`.po`/`.mo`): a mensagem é achada só pelo texto em inglês, então os contextos do Qt se juntam (vale a tradução mais comum do texto); `%1` vira `%1$s` quando o texto daqui usa `%s`. Só traduz o texto que é idêntico ao do upstream (cerca de 64% dos textos em pt_BR, 47 a 63% em outros; o resto aparece em inglês); línguas sem nenhuma tradução no upstream (eu_ES, ja_JP, sq_AL, zh_Hans) não são instaladas; nomes das línguas numa tabela fixa (`QLocale.nativeLanguageName`); `zh_Hans` instala como `zh_CN` | os textos do port nem sempre são os do Qt Designer (outra janela, outro toolkit); os botões padrão do GTK (`GTK_STOCK_*`) vêm dos catálogos do próprio GTK. Sob o locale C, um idioma escolhido ainda funciona (`LC_MESSAGES` vai para `C.UTF-8`) |
| 103 | `daemon/procmon/events.c` | o conector de processos sempre faz `setns()` para o namespace de rede do PID 1 e volta, o que exige `CAP_SYS_ADMIN` mesmo quando o daemon já está nele | só faz o `setns()` se o namespace de `/proc/1/ns/net` for outro (mesmo `st_dev` e `st_ino`: não faz) | permite tirar `CAP_SYS_ADMIN` do daemon (`docs/PRIVILEGES.md`); o resultado é o mesmo |

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
- Tarefas: `pid-monitor` e `sockets-monitor` nunca param ao desconectar
  (divergência 86); asserções de tipo sem verificação nos dados das tarefas
  derrubam o daemon, e o `sockets-monitor` chama `SetID` antes de verificar
  o erro de `New` (divergência 41).
- Tarefas do disco: o IOC-scanner só roda de verdade na primeira vez
  (divergência 92); o downloader escreve por cima da lista sem truncar
  (divergência 93); `Tasks.ConfigPath` na configuração da partida derruba o
  daemon (divergência 95); `Start` do downloader devolve o erro do
  tempo-limite por cima do erro do intervalo.
- `LoadTaskFile`, ao mudar o arquivo de uma tarefa, escolhe a tarefa pelo
  nome da instância (`taskConf.Name`) em vez do tipo da lista: só reinicia
  instâncias chamadas `looper`, `downloader` ou `IOC-scanner`; as outras são
  removidas e não voltam. Tarefas que saem do `tasks.json` continuam
  rodando. O port reproduz.
- O agendador nunca dispara com horas+minutos ou horas+segundos sem o
  terceiro campo, nem sem `weekday`. O port reproduz.
- Loggers: o `syslog` ignora o `Tag` configurado (o `syslog.New` usa a
  constante `opensnitch`) e, no formato padrão, manda uma linha RFC 5424 com
  hostname e tag vazios dentro da linha do próprio `log/syslog` (cabeçalho
  duplo); o `Remote` não usa `formatLine`, então as linhas CSV vão sem
  quebra de linha. O port reproduz.
- `readDescriptors` escreve o nome do descritor onde deveria ir o inode
  (`socket:[<fd>] - ...`). O port reproduz.
- `PacketDiagMsg.deserialize` lê os atributos por deslocamentos fixos e toma
  o `PACKET_DIAG_INFO` (também de 28 bytes) pelo `PACKET_DIAG_MCLIST`, um
  byte adiantado e em big-endian: o índice da interface dos sockets
  AF_PACKET fica só com o byte baixo. O port reproduz.
- As opções `{IPPROTO_RAW, AF_PACKET}` e `{IPPROTO_UDP, AF_PACKET}` do
  `sockets-monitor` vão ao kernel como `inet_diag_req_v2`, que o
  `packet_diag` recusa (protocolo diferente de zero): nunca dão sockets.
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
- O cache de DNS (`dns/track.go`) guarda um nome por IP e mapeia o alvo de
  um CNAME de volta para o alias: depois de resolver
  `alias.exemplo.test` (CNAME `exemplo.test`), conexões para `exemplo.test`
  passam a ter `dest.host` igual a `alias.exemplo.test`; um IP compartilhado
  por vários nomes (CDN) fica com o último nome resolvido. O port reproduz
  (teste de integração "after the alias, the canonical name maps to it").
- Respostas DNS por TCP nunca entram no cache: a regra do nftables só
  enfileira `udp sport 53`, `TrackAnswers` só olha UDP, e em `getDomains` o
  gopacket nunca decodifica DNS sobre TCP (`DecodeStreamsAsDatagrams`
  desligado). Respostas grandes (TC) refeitas por TCP deixam o IP sem nome.
  O port reproduz.
- UDP da porta 53 para uma porta que o gopacket associa a outra camada
  (123/NTP, 67-68/DHCP, 4789/VXLAN...) não é decodificado como DNS: não
  entra no cache e segue o caminho normal. O port reproduz.
- O cache nunca é limpo (ver divergência 31).
- `initSystemdResolvedMonitor` declara `resolvMonitor` com `:=`, escondendo
  a variável global: `doCleanup` nunca fecha o monitor. Inofensivo na
  saída. O port fecha.
- `connPoller` do monitor do systemd-resolved reconecta uma vez só (ver
  divergência 34).
- `getClientConfig()` manda como `Id` o `UnixNano()` de um `time.Time`
  zerado (estoura o int64: 11651379494838206464). O port reproduz.
- `Statistics.SetLimits` imprime "max events" e "max stats" trocados. O port
  reproduz.
- "UI connected, dispathing queued alerts: %d" imprime o tamanho do canal de
  entrada (quase sempre 0), não o da fila de alertas guardados. O port
  reproduz.
- `NewAlert` testa `case procmon.Process:` e converte para
  `*procmon.Process`: alerta com processo nunca é montado (ou entra em
  pânico se receber o valor). Sem uso hoje (só o ebpf manda processos).
- `ENABLE_RULE`/`DISABLE_RULE` com regra sem operador: ponteiro nulo (ver
  divergência 42).
- `TASK_START` de `pid-monitor`/`node-monitor` com `Data` que não é objeto
  retorna sem responder à UI.
- `CHANGE_CONFIG` aplica o config duas vezes (no handler e de novo quando o
  fsnotify vê o arquivo gravado), e o handler não atualiza o config em uso:
  só a recarga pelo arquivo faz isso. O port reproduz.
- Nas estatísticas, conexão sem regra conta como `Dropped` mesmo quando a
  ação padrão a deixou passar. O port reproduz.
- `unix-abstract:` nunca conecta (divergência 43).
- UI: `Utils.check_versions` quebra com versão que não seja `x.y.z`, e o
  `Ping` dela descarta as estatísticas nesse caso (divergência 44).
- UI, popup: o aviso de checksum busca as regras com `records.first()` e
  depois `records.next()`, pulando a primeira; com uma só regra para o
  caminho, o aviso nunca aparece. O port reproduz.
- UI, popup: `get_rule_by_field` usa `LIKE '%caminho%'`, então `%` e `_` no
  caminho são curingas e casa também regras de outros caminhos que contêm
  este. O port reproduz.
- UI: `DEFAULT_DURATION_IDX = 6` tem o comentário "until restart", mas o
  índice 6 do combo é `12h`: a duração padrão de uma instalação nova é 12h.
  O port reproduz.
- UI: `duration.to_seconds` usa dia de 60 horas e semana de 60 dias. O port
  reproduz (só afeta quando a regra é desativada na tabela da UI).
- UI: `Nodes.get_addr` de um peer IPv6 (`ipv6:[::1]:1234`) dá `ipv6:[`:
  todos os nós IPv6 viram o mesmo nó. O port reproduz.
- UI: `AskRule` com duração filtrada (`default_ignore_rules`) apaga a regra
  pelo peer cru (`unix:`) em vez do endereço do nó (`unix:/local`), e nada
  é apagado. O port reproduz.
- UI: no `desktop_parser`, o `IN_DELETE` do inotify procura o caminho do
  arquivo no campo da descrição e nunca remove nada. O port reproduz.
- UI: o sinal `_notification_callback` nunca é conectado: erros nas
  respostas às notificações (ligar/desligar interceptação) não aparecem. O
  port os registra no log.
- UI, popup: "Update rule" (aviso de checksum) percorre a lista de regras a
  partir da primeira e para depois de uma: atualiza a primeira, não a
  selecionada. O port reproduz.
- UI: `global/max_clients` do settings.conf só vale se `--max-clients`
  também for passado. O port reproduz.
- UI: com o grpc-go, o `:authority` das chamadas por socket Unix é o caminho
  do socket (`///tmp/osui.sock`), inválido em HTTP/2; o grpc core aceita, o
  nghttp2 com validação não (ver `docs/PROTOCOL.md`).
- Firewall de sistema (fase 8):
  - `iptables`: `AddSystemRule` aplica a regra legada mesmo com `Enabled:
    false` (a do `system-fw.json` padrão, `-p icmp -j ACCEPT`, sempre entra);
    `ConfigureChainPolicy` passa o gancho em minúsculas (`-P input`), o que o
    iptables recusa. O port reproduz.
  - `nftables`: `restoreBackupChains` recria, com policy accept, toda cadeia
    que tinha policy accept quando o daemon iniciou, mesmo que o dono a tenha
    apagado nesse meio tempo. O port reproduz.
  - `NewExprIP` usa offsets de IPv4 também para `ip6` e para endereços IPv6
    (a regra é recusada pelo kernel); `NewExprNATFlags` só reconhece as flags
    se o parâmetro inteiro for a lista delas ("random,persistent"), e aí o
    endereço não é lido. `reject with icmpv6` usa o tipo `NFT_REJECT_TCP_RST`.
    O port reproduz.
  - `limit` com `rate-units` diferente de kbytes/mbytes troca a taxa pelo
    número lido da unidade (normalmente 0). O port reproduz.
  - O daemon 1.6 não recarrega o firewall quando o `Firewall` do
    `default-config.json` muda (corrigido depois).
  - UI: `delete_profile` compara a policy (texto) com o perfil inteiro
    (dicionário) e nunca a restaura; apaga por índices calculados antes de
    apagar. O port reproduz. Ver também as divergências 83 a 85.

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
  (`unshare -Urn`), onde o kernel permite. Nunca na rede do host. Com mount
  namespace (`-m`), os testes de DNS trocam `/etc/resolv.conf` e
  `/etc/nsswitch.conf` só dentro dele.
- **DNS e resolvedores:** como no upstream, os nomes vêm de duas fontes, e
  nenhuma depende de systemd:
  1. respostas DNS na fila do nfqueue (regra `udp sport 53` na cadeia de
     entrada, sem filtro de interface). Cobre qualquer resolvedor que fale
     DNS em UDP: servidor remoto direto pelo `resolv.conf` (Devuan e
     similares), dnsmasq/unbound/stubby/dnscrypt-proxy locais e o stub
     127.0.0.53 do systemd-resolved, porque a resposta ao programa passa
     pelo `lo`;
  2. o monitor varlink do systemd-resolved, se o socket
     `/run/systemd/resolve/io.systemd.Resolve.Monitor` existir (systemd 252
     ou mais novo) quando o daemon sobe. Pega também respostas servidas do
     cache do resolved a programas que usam `nss-resolve` (sem pacote DNS).
     O varlink é falado direto (JSON terminado em NUL num socket Unix), sem
     libsystemd.

  Sem resolved (Devuan, systemd antigo), o monitor não sobe e só a fila é
  usada. O que nenhuma das duas vê, igual ao upstream: buscas respondidas
  pelo cache do `nscd`, DNS sobre TCP, e DoH/DoT feitos pelo próprio
  programa.
- **gRPC e protobuf:** nghttp2 + protobuf-c (dependências previstas), sem a
  biblioteca oficial do gRPC. O transporte em `common/grpc/` não depende do
  loop do daemon (a UI da fase 6 vai usá-lo com o loop do GLib): quem o usa
  observa o fd e chama `ks_grpc_conn_on_io()`/`ks_grpc_conn_tick()`.
  Mensagens montadas para envio usam uma arena (`common/arena.c`) e são
  liberadas de uma vez depois do `pack`. Notas do protocolo em
  `docs/PROTOCOL.md`.
- **UI:** GTK 2 só nas janelas (`ui/prompt.c`, `ui/tray.c`, `ui/main.c`);
  o resto da UI (`libui.a`: servidor, serviço, nós, regras, settings,
  popup sem widgets, `.desktop`) usa só GLib e é testado sem display. O
  servidor gRPC roda no loop do GLib (`g_unix_fd_add`), sem threads. Até a
  fase 7 a tabela de regras da UI fica em memória (o upstream também usa
  SQLite em memória por padrão). Os ícones e o `network_aliases.json` do
  upstream são embutidos no binário. O `settings.conf` é gravado como o
  Qt 6 (UI 1.8.0) grava: UTF-8; o que o Qt 5 (UI 1.6.x) gravou com `\x`
  também é lido.
- **Versão:** `0.1.0+os1.8.0` (`config.mk`). Betas usarão til
  (`1.0.0~beta1+os...`) para o dpkg ordenar antes da versão final.
