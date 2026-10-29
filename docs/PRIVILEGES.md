# Privilégios do daemon

`kisnitchd` precisa ser root para interceptar conexões, mas não de **todos** os
poderes do root. As unidades (`packaging/systemd/kisnitch.service` e
`packaging/sysvinit/kisnitch`) tiram o resto. A UI (`kisnitch-gtk`) roda como o
usuário, sem privilégio nenhum.

## Capabilities que ficam

| Capability | Para quê | Onde |
|---|---|---|
| `CAP_NET_ADMIN` | fila do nfqueue, regras do nftables, `SO_RCVBUFFORCE` do socket da fila, o conector de processos | `daemon/intercept.c`, `daemon/fw/`, `daemon/procmon/events.c` |
| `CAP_SYS_PTRACE` | ler `/proc/PID/{exe,cwd,fd,environ,maps,...}` de processos de outros usuários (o kernel exige o direito de ptrace) | `daemon/procmon/` |
| `CAP_DAC_OVERRIDE` | conectar ao socket da UI (é do usuário, modo 0640: o root precisa de permissão de escrita), ler os executáveis para os checksums e o `IOC-scanner` | `daemon/uiclient.c`, `daemon/procmon/`, `daemon/tasks/` |
| `CAP_NET_RAW` | só com `"Firewall": "iptables"`: o `iptables` legado abre um socket raw | `daemon/fw/iptables.c` |

Fica de fora, entre outras: `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SETUID`/`SETGID`,
`CAP_CHOWN`, `CAP_FOWNER`, `CAP_KILL`, `CAP_SYS_RAWIO`, `CAP_SYS_BOOT`.

### Sem `CAP_SYS_ADMIN`

O conector de processos só funciona no namespace de rede do PID 1. O upstream
faz `setns()` para lá sempre, e o kernel pede `CAP_SYS_ADMIN` até para entrar
no namespace em que já se está. O port só faz o `setns()` se o namespace for
outro (compara `st_dev`/`st_ino` de `/proc/self/ns/net` e `/proc/1/ns/net`).
Divergência 103 em `docs/UPSTREAM.md`.

## Sandbox do systemd

Além do conjunto de capabilities (`CapabilityBoundingSet`), `NoNewPrivileges`:

- `ProtectSystem=full` com `ReadWritePaths=/etc/opensnitchd` (`/usr`, `/boot`
  e `/etc` ficam só para leitura, menos onde o daemon grava regras,
  configuração e `system-fw.json`); `ProtectHome=read-only`. Sem `PrivateTmp`:
  o socket da UI é `/tmp/osui.sock`.
- `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`, `ProtectClock`,
  `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`,
  `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute` (o daemon
  não usa JIT; o pcre2 é chamado sem JIT).
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`.
- `SystemCallFilter=@system-service` com `SystemCallErrorNumber=EPERM`: uma
  syscall fora da lista falha com erro em vez de matar o daemon.

No sysvinit só dá para limitar as capabilities: o script usa
`setpriv --bounding-set` e `--no-new-privs` (util-linux, presente no Devuan).
Se o `setpriv` recusar (container sem alguma das capabilities), o daemon roda
com o que o container permite, nunca com mais. `CAPS=` vazio em
`/etc/default/kisnitch` desliga a restrição.

## Como foi verificado

1. `strace -f` do daemon durante `tests/integration/ui.sh` (interceptação,
   regras, UI, tarefas): 51 syscalls, todas dentro de `@system-service`; as
   únicas recusas por permissão eram `/proc/PID/fd` e `/proc/1/ns/net` de
   processos de fora do user namespace de teste (`CAP_SYS_PTRACE`) e o
   `SO_RCVBUFFORCE` (`CAP_NET_ADMIN`).
2. `ui.sh` (24/24) e `sysfw.sh` (39/39) com o daemon sob
   `setpriv --bounding-set -all,+net_admin,+net_raw,+sys_ptrace,+dac_override`.
   Sem `+net_admin` o `ui.sh` falha: o daemon não sobe.
3. `tests/integration/replace-test` (CI, `tools/replace-test.sh`): o daemon
   iniciado pelo script de init tem `CapBnd = 0000000000083002`.

O que **não** foi exercitado: `CAP_DAC_OVERRIDE` e `CAP_SYS_PTRACE` com
processos de outro usuário de verdade (os testes rodam num user namespace, onde
todos os usuários são o mesmo) e a unidade systemd rodando (não há systemd
como PID 1 no ambiente de testes nem nos containers do CI). Se algo quebrar sob
a unidade, `journalctl -u kisnitch` mostra o `EPERM`; um drop-in
(`systemctl edit kisnitch`) afrouxa o que for preciso.

## Métodos que precisam de mais

- `ProcMonitorMethod: audit`: o daemon executa o `auditctl`
  (`CAP_AUDIT_CONTROL`); adicione-a ao `CapabilityBoundingSet` num drop-in.
- `ProcMonitorMethod: ebpf` (fase 9, adiada): carregar programas pediria
  `CAP_BPF`/`CAP_PERFMON` ou `CAP_SYS_ADMIN`.
- `Rules.Path` ou `FwOptions.ConfigPath` fora de `/etc/opensnitchd`: liste o
  diretório em `ReadWritePaths=`.
