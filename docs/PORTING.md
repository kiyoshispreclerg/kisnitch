# Plano de Port: OpenSnitch → C + GTK2

> Documento de referência para desenvolvimento com Claude Code.
> Coloque este arquivo em `docs/PORTING.md` e crie um `CLAUDE.md` na raiz apontando para ele (modelo na seção 10).

---

## 1. Objetivo

Reimplementar o OpenSnitch (firewall de aplicação para Linux) em **C11** com interface em **GTK2** (compatível com gtk2-ng), mantendo:

- **Todas as funcionalidades** do daemon e da UI originais.
- **Compatibilidade total de arquivos**: `default-config.json`, regras em `rules/*.json`, `system-fw.json`, `network_aliases.json` e listas de bloqueio são lidos e escritos no mesmo formato do original.
- **Compatibilidade de protocolo** (gRPC, `proto/ui.proto`): nosso daemon funciona com a UI Python original e a UI original funciona com nosso daemon. Isso é o que torna o port testável por comparação direta.

Metas de leveza (medir a partir da Fase 3):

| Componente | Meta |
|---|---|
| Daemon, RSS ocioso | < 5 MB |
| UI, RSS ocioso (só bandeja) | < 20 MB |
| Build do zero | `make` com apenas gcc, pkg-config e libs de sistema |
| Dependências de runtime | somente bibliotecas C presentes em qualquer distro |

### Licença

O OpenSnitch é **GPL-3.0**. Este port é obra derivada: usar GPL-3.0, manter os avisos de copyright originais nos arquivos traduzidos e dar crédito ao projeto upstream no README.

---

## 2. Dependências

Todas em C, empacotadas em todas as distros principais.

| Função | Biblioteca | Obrigatória? |
|---|---|---|
| Fila de pacotes | `libnetfilter_queue` | sim |
| Netlink / nftables | `libmnl`, `libnftnl` | sim |
| Conntrack (marcas) | `libnetfilter_conntrack` | sim |
| JSON | `json-c` (ou `cJSON` vendorizado, um arquivo só) | sim |
| Regex | `pcre2` | sim |
| Protobuf | `protobuf-c` | sim |
| HTTP/2 (transporte gRPC) | `nghttp2` | sim |
| TLS para nós remotos | `openssl` | opcional (`TLS=1`) |
| eBPF | `libbpf`, `clang` só no build dos módulos | opcional (`EBPF=1`) |
| Banco de estatísticas (UI) | `sqlite3` | sim (UI) |
| Interface | `gtk+-2.0` | sim (UI) |
| Notificações | `libnotify` | opcional (`NOTIFY=1`) |

**Build:** `Makefile` simples + `pkg-config`. Sem autotools, sem meson, sem cmake. Flags opcionais via `make EBPF=1 TLS=1 NOTIFY=1`.

**Sobre o gRPC:** não usar a biblioteca oficial gRPC (é C++ e pesada). Implementar um cliente/servidor gRPC mínimo sobre `nghttp2` + `protobuf-c`. O gRPC é só HTTP/2 com um framing de 5 bytes (1 byte de compressão + 4 bytes de tamanho) e alguns headers (`content-type: application/grpc`, `grpc-status` nos trailers). Só precisamos de chamadas unárias e de um stream bidirecional (`Notifications`), via socket Unix e opcionalmente TCP.

---

## 3. Estrutura do repositório

```
/
├── CLAUDE.md                 # instruções para o Claude Code
├── Makefile
├── config.mk                 # flags opcionais, paths de instalação
├── docs/
│   ├── PORTING.md            # este documento
│   ├── UPSTREAM.md           # mapeamento Go/Python → C e último commit sincronizado
│   └── PROTOCOL.md           # notas do gRPC mínimo
├── upstream/                 # git submodule do evilsocket/opensnitch (somente leitura)
├── proto/ui.proto            # cópia do upstream, gerada por script
├── common/                   # código compartilhado daemon + UI
│   ├── grpc/                 # framing gRPC sobre nghttp2 (cliente e servidor)
│   ├── pb/                   # código gerado pelo protoc-c (não editar à mão)
│   ├── json_util.c           # helpers sobre json-c
│   ├── log.c
│   ├── list.h, hash.h        # estruturas de dados simples
│   └── duration.c            # parse de "30s", "5m", "until restart", etc.
├── daemon/
│   ├── main.c                # args, sinais, loop principal (epoll)
│   ├── config.c              # default-config.json + recarga
│   ├── queue.c               # nfqueue, veredictos assíncronos
│   ├── conn.c                # objeto de conexão (parse IPv4/IPv6, TCP/UDP/ICMP/SCTP...)
│   ├── netstat.c             # /proc/net/* e sock_diag
│   ├── procmon/
│   │   ├── proc.c            # método "proc"
│   │   ├── ebpf.c            # método "ebpf" (EBPF=1)
│   │   ├── audit.c           # método "audit"
│   │   └── cache.c           # cache de processos (path, cmdline, env, cwd, hashes, árvore de pais)
│   ├── dns/
│   │   ├── parse.c           # parser de respostas DNS (fuzzado)
│   │   ├── cache.c           # IP → hostname
│   │   └── ebpf.c            # uprobes de resolução (EBPF=1)
│   ├── rules/
│   │   ├── rule.c            # estrutura, precedência, durações
│   │   ├── operator.c        # simple, regexp, list, network, lists
│   │   ├── loader.c          # diretório de regras, monitoramento (inotify)
│   │   └── lists.c           # listas de domínios/IPs/redes em arquivo
│   ├── fw/
│   │   ├── nft.c             # backend nftables (libnftnl)
│   │   ├── iptables.c        # backend iptables (fork/exec do binário)
│   │   └── sysfw.c           # system-fw.json, monitor de regras removidas
│   ├── stats.c
│   ├── tasks.c               # tarefas sob demanda (monitor de pid, de nó, etc.)
│   └── uiclient.c            # cliente gRPC: Ping, AskRule, Subscribe, Notifications, PostAlert
├── ebpf/                     # módulos eBPF copiados do upstream (já são C)
├── ui/
│   ├── main.c
│   ├── server.c              # servidor gRPC integrado ao main loop do GLib
│   ├── nodes.c               # múltiplos daemons conectados
│   ├── tray.c                # GtkStatusIcon
│   ├── prompt.c              # janela de permissão com contagem regressiva
│   ├── stats_win.c           # janela principal com abas
│   ├── rules_editor.c
│   ├── prefs.c
│   ├── fw_editor.c
│   ├── db.c                  # SQLite (memória ou arquivo)
│   ├── desktop.c             # parser de .desktop para ícones/nome de apps
│   └── settings.c            # leitura/escrita do settings.conf (formato INI do QSettings)
├── tests/
│   ├── unit/                 # testes sem root
│   ├── fixtures/             # JSONs copiados do upstream e casos próprios
│   ├── integration/          # testes com netns (precisam de root)
│   ├── fuzz/                 # alvos libFuzzer/AFL
│   └── harness.h             # mini framework de teste (um header, sem dependência)
├── tools/
│   ├── upstream-diff.sh      # lista mudanças do upstream desde o último sync
│   ├── sync-proto.sh         # copia ui.proto e regenera common/pb
│   └── sync-ebpf.sh          # copia os módulos eBPF
└── packaging/
    ├── systemd/  openrc/  runit/
    ├── debian/  arch/PKGBUILD
```

**Nomes dos binários** (renomeie à vontade): `osnitchd` (daemon) e `osnitch-gtk` (UI). Paths de configuração são os mesmos do original (`/etc/opensnitchd/`, `~/.config/opensnitch/`) para permitir troca direta.

---

## 4. Decisões de arquitetura

### Daemon

- **Um loop `epoll`** com: fd do nfqueue, fd(s) de netlink, socket do gRPC, `timerfd` para timeouts e `inotify` para regras/config. Sem threads no caminho principal.
- **Veredictos assíncronos.** O nfqueue aceita veredicto fora de ordem pelo `packet_id`. Quando uma conexão precisa perguntar à UI, ela vai para uma tabela de pendentes (chave: `packet_id`), o loop continua processando outros pacotes, e a resposta da UI (ou o timeout → ação padrão) dispara o veredicto. Isso evita travar a rede enquanto o popup está aberto.
- **Pool pequeno de workers (pthreads)** apenas para operações lentas e bloqueantes: hash MD5 de executáveis, leitura de `/proc` sob carga. Comunicação com o loop via `eventfd`.
- **Memória:** cada estrutura tem dono explícito, documentado em comentário no header. Sem alocação no caminho quente quando der para usar pool/arena.
- **Segurança:** o daemon roda como root e faz parse de pacotes vindos da rede. Todo parser (DNS, conexão, JSON vindo da UI) precisa ter alvo de fuzzing e passar limpo em ASan/UBSan.

### UI

- **Servidor gRPC dentro do main loop do GLib** via `g_unix_fd_add`. Sem threads extras.
- **Estado em SQLite**, igual ao original (em memória por padrão, arquivo opcional).
- **Configuração** em `~/.config/opensnitch/settings.conf`, no formato INI que o QSettings grava, para permitir alternar entre a UI original e a nossa.
- **Uma janela por arquivo `.c`**, construída em código (sem Glade/GtkBuilder, para não depender de arquivos externos e manter o binário autocontido).

---

## 5. Fases de desenvolvimento

Cada fase termina com **critérios de aceite verificáveis**. Não avançar de fase com critério pendente.

Regra geral para todas as fases: antes de escrever código, ler os arquivos correspondentes em `upstream/` e registrar o mapeamento em `docs/UPSTREAM.md`. Nunca inventar campos de JSON, nomes de operandos ou mensagens do protocolo; tudo vem do fonte original.

### Fase 0 — Fundação

- Repositório, `Makefile`, `config.mk`, submodule `upstream/` fixado na última tag estável (conferir com `git tag`).
- `tests/harness.h`, alvo `make test`, alvo `make asan` (build com `-fsanitize=address,undefined`).
- `common/log.c`, `common/json_util.c`, `common/duration.c`.
- `daemon/config.c`: carregar `default-config.json` com todos os campos que o upstream reconhece, valores padrão iguais aos do Go.
- CI: build com gcc e clang, `-Wall -Wextra -Werror`, testes, ASan, `cppcheck`.

**Aceite:**
- [x] `make && make test` passa sem warnings em gcc e clang.
- [x] O config de exemplo do upstream carrega e, ao ser regravado, produz JSON semanticamente igual (teste de ida e volta).
- [x] Config inválido gera erro claro e não derruba o processo.

### Fase 1 — Motor de regras (sem root, sem rede)

- `rules/rule.c`, `operator.c`, `loader.c`, `lists.c`.
- Todos os tipos de operador (`simple`, `regexp`, `list`, `network`, `lists`) e todos os operandos que o upstream suporta (processo, usuário, destino, origem, protocolo, interfaces, variáveis de ambiente, hash, listas, etc.: extrair a lista exata de `upstream/daemon/rule/`).
- Flags `sensitive`, `enabled`, `precedence`, `nolog`; ações `allow`, `deny`, `reject`; durações temporárias.
- Ordem de avaliação idêntica à do upstream (conferir no loader como as regras são ordenadas e como a precedência interrompe a busca).
- Recarga por `inotify`, regras temporárias expirando via timer.

**Aceite:**
- [x] Todas as regras de exemplo/teste do upstream carregam.
- [x] Teste de tabela: para cada operador, casos que casam e que não casam, incluindo regex inválida, lista vazia, rede IPv6, e operandos ausentes na conexão.
- [ ] **Teste diferencial** (opcional, só na máquina de desenvolvimento): corpus de pares (regra, conexão simulada) avaliado pelo código Go do upstream e pelo nosso, com resultados idênticos. O harness Go fica em `tests/diff/` e não entra no build normal.
- [x] Regra com duração `30s` some após 30s.

### Fase 2 — Netstat e monitor de processos (método proc)

- `netstat.c`: parse de `/proc/net/{tcp,tcp6,udp,udp6,udplite,udplite6,raw,raw6}` e consulta via `sock_diag` (netlink), conforme o upstream usa cada um.
- `procmon/proc.c` + `cache.c`: inode do socket → PID → path, cmdline, env, cwd, UID, árvore de processos pais, hashes.
- Cache com invalidação quando o processo morre ou é substituído (exec).

**Aceite:**
- [x] Teste abre um socket TCP e UDP no próprio processo e o netstat encontra o PID correto.
- [x] Teste com processo filho (`fork` + `exec`) identifica path e pai corretamente.
- [x] Cache não cresce indefinidamente (teste com 10 mil processos curtos, RSS estável).

### Fase 3 — Interceptação mínima (primeiro binário útil)

- `queue.c`: nfqueue, parse de pacote em `conn.c`, veredicto.
- `fw/nft.c`: criar tabelas/cadeias/regras de interceptação iguais às do upstream (conferir em `upstream/daemon/firewall/nftables/`), incluindo marcas de conntrack para não reavaliar conexões já decididas e a opção `QueueBypass`.
- Sem UI ainda: conexões sem regra recebem `DefaultAction`.
- Limpeza completa ao sair (SIGTERM, SIGINT) e ao reiniciar; monitor que reinstala as regras se forem removidas externamente.

> Nota (conferido no upstream): o backend nftables não usa marcas de conntrack. Conexões já decididas não voltam à fila porque as regras só enfileiram o SYN do TCP e `ct state new,related` dos demais protocolos. O conntrack só é usado em `FlushConnections` (`Internal.FlushConnsOnStart`). Ver `docs/UPSTREAM.md`.

**Aceite (testes de integração em network namespace: `make test-integration`, como root ou num user namespace):**
- [x] Regra `deny` para `curl` faz o curl falhar; regra `allow` faz funcionar.
- [x] Conexão sem regra segue a `DefaultAction`.
- [x] Após `kill` do daemon, `nft list ruleset` não tem nada nosso (ou a rede continua funcionando se `QueueBypass` estiver ativo).
- [x] `nft flush ruleset` com o daemon rodando → regras reinstaladas dentro do intervalo de monitoramento.
- [x] Medição: RSS ocioso e sob 1000 conexões/s. Registrar em `docs/BENCH.md`.

### Fase 4 — DNS

- `dns/parse.c`: captura de respostas DNS (mesmo mecanismo que o upstream usa no nfqueue) e cache IP → hostname, para que regras por `dest.host` funcionem.
- Integração com systemd-resolved se o upstream suportar (conferir em `upstream/daemon/dns/`).

> Nota (conferido no upstream): o systemd-resolved é opcional. O upstream lê os nomes de duas fontes: as respostas DNS na fila (regra `udp sport 53`, que pega qualquer resolvedor em UDP, inclusive caches locais via `lo`) e, se o socket existir, o monitor varlink do resolved. O port fala varlink direto, sem libsystemd; sem resolved (Devuan) só a fila é usada. Ver "DNS e resolvedores" em `docs/UPSTREAM.md`.

**Aceite:**
- [x] Regra por domínio bloqueia `curl https://exemplo` dentro do netns com resolver de teste.
- [x] Alvo de fuzzing do parser roda 1 hora sem crash em ASan (`fuzz_dns`: 230 milhões de execuções em 3600 s, 2026-10-09; `fuzz_packet`, que passa pelo mesmo parser, idem).
- [x] Respostas truncadas, com ponteiros de compressão em laço e tamanhos inválidos são rejeitadas sem leitura fora dos limites.

### Fase 5 — Protocolo (daemon ↔ UI)

- `common/grpc/`: framing gRPC sobre nghttp2, cliente e servidor, socket Unix (`unix:///tmp/osui.sock` ou o que estiver no config) e TCP.
- `daemon/uiclient.c`: todas as RPCs do `ui.proto` (Ping com estatísticas, AskRule, Subscribe, Notifications bidirecional, PostAlert e o que mais existir na versão fixada).
- Tratar todos os tipos de notificação/comando que a UI envia ao daemon (ligar/desligar interceptação, alterar config, criar/alterar/apagar regras, recarregar firewall, tarefas, etc. — extrair a lista do `ui.proto` e do handler no Go).
- Reconexão automática quando a UI cai.

**Aceite:**
- [x] **Nosso daemon + UI Python original**: popup aparece, resposta cria regra, estatísticas aparecem, mudanças de preferência chegam ao daemon.
  Verificado em parte (2026-10-13): o fluxo completo contra uma UI falsa em grpcio (`tests/integration/run.sh`, seção 6: pergunta, regra criada e gravada, `Ping` com estatísticas, `CHANGE_CONFIG` aplicado e gravado), e contra a UI original 1.6.5 sem tela (Qt `offscreen`): Subscribe, canal de notificações e Ping sem erros, popup que expira e vira regra no daemon. Teste manual na sessão gráfica com a UI 1.6.5 instalada (2026-10-13, relato do usuário: funcionando bem). Não testado com a UI 1.8.0 (precisa de PyQt6); a 1.6.5 fala o mesmo protocolo (o `ui.proto` só ganhou campos).
- [x] UI fechada → daemon usa ação padrão sem travar; UI reaberta → reconecta. (`run.sh`, seção 6: "UI closed: no waiting", "the daemon reconnects when the UI comes back".)
- [x] Timeout de pergunta respeita o configurado. O prazo é da UI: com a UI original 1.6.5 configurada para 7 s e `allow`, o curl passou em 7 s e a regra foi criada. Do lado do daemon, o prazo de 120 s do upstream (`KS_UI_ASK_TIMEOUT_NS`) aplica a ação padrão se a UI não responder.

### Fase 6 — UI base em GTK2

- `ui/server.c`, `nodes.c`, `tray.c`, `prompt.c`, `settings.c`.
- Popup completo: info do processo e destino, ícone e nome via `.desktop`, contagem regressiva, escolha de ação, duração e alvo da regra (por path, cmdline, host, IP, porta, usuário, combinações — igual ao original), opção de detalhes expandidos.
- Ícone de bandeja com estados (conectado, desconectado, interceptação desligada) e menu.

**Aceite:**
- [x] **Daemon Go original + nossa UI**: fluxo completo de pergunta e criação de regra funciona.
  `tests/integration/ui.sh` (netns + Xvfb): conexão, popup, timeout com `allow` e com `deny`, clique em "Allow", regra gravada pelo daemon e aplicada sem perguntar de novo. Verificado em 2026-10-14 com o `opensnitchd` 1.6.5 instalado na máquina de desenvolvimento (16/16). Com o daemon da tag fixada (1.8.0, compilado do submódulo): job `interop-ui` do CI, que precisa de Go (não há Go nesta máquina).
- [x] **Nosso daemon + nossa UI**: idem (`tests/integration/ui.sh`, dentro de `make test-integration`).
- [x] Regra criada pela nossa UI é byte a byte compatível (após normalização do JSON) com a que a UI original criaria para a mesma resposta.
  `make diff-ui` (`tests/diff/prompt/`): 2584 casos (15 tipos de conexão, cada entrada dos combos, ações, durações, padrões do settings, opções avançadas, nomes já usados) passam pelo próprio código Python do popup do upstream 1.8.0 (com o Qt substituído) e pelo nosso; combos e regra (nome, ação, duração, operador, lista) idênticos. O daemon recebe a mesma mensagem `Rule`, então grava o mesmo arquivo (a não ser `created`).
- [x] RSS da UI ociosa medido e registrado: `docs/BENCH.md`, fase 6. 27,6 MB ocioso (5 MB próprios); a meta de 20 MB da seção 1 não é atingível com GTK 2 nesta máquina (um programa GTK 2 vazio com ícone de bandeja já ocupa 27–30 MB). A UI original ocupa 140–220 MB.

### Fase 7 — UI completa

- `stats_win.c`: todas as abas do original (eventos, nós, regras, hosts, aplicações, endereços, portas, usuários e demais que existirem na versão fixada), filtros, busca, menu de contexto, exportação.
- `rules_editor.c`: criar/editar todos os tipos de operador, inclusive listas e regras compostas.
- `prefs.c`: todas as opções da UI e do daemon (por nó).
- `db.c`: esquema SQLite compatível com o do original, limpeza por limite de eventos.

**Aceite:**
- [ ] Checklist gerado a partir dos arquivos `.ui` do upstream (cada widget/opção existente lá tem equivalente aqui). Gerar com script e manter em `docs/UI-CHECKLIST.md`.
- [ ] 100 mil eventos na tabela sem travar a interface (paginação/virtualização no `GtkTreeView`).

### Fase 8 — Firewall de sistema

- `fw/sysfw.c`: `system-fw.json` completo (cadeias, políticas, regras com expressões).
- `fw/iptables.c`: backend iptables.
- `ui/fw_editor.c`: editor de regras de sistema.

**Aceite:**
- [ ] Os `system-fw.json` de exemplo do upstream aplicam e produzem o mesmo ruleset que o daemon Go (comparar `nft list ruleset` normalizado).
- [ ] Troca de backend em tempo de execução sem deixar resíduo.

### Fase 9 — eBPF (opcional, `EBPF=1`)

- Copiar módulos de `upstream/ebpf_prog/` com `tools/sync-ebpf.sh`.
- `procmon/ebpf.c`, `dns/ebpf.c`, rastreamento de exec/exit via `libbpf`.
- Fallback automático para o método `proc` se o kernel não suportar.

**Aceite:**
- [ ] Mesmos testes da Fase 2 e 4 passam com `ProcMonitorMethod: ebpf`.
- [ ] Kernel sem BTF/eBPF → log de aviso e fallback, sem falhar.

### Fase 10 — Restante

- Monitor `audit`, tarefas (`tasks.c`), alertas, loggers remotos/syslog, autenticação TLS de nós remotos (`TLS=1`), notificações (`NOTIFY=1`), i18n com gettext (converter os `.ts` do Qt para `.po` com script).

**Aceite:**
- [ ] Tabela de funcionalidades em `docs/UPSTREAM.md` 100% marcada como portada, ou com justificativa explícita para o que ficou de fora.

### Fase 11 — Empacotamento e endurecimento

- Units para systemd, OpenRC e runit; PKGBUILD e pacote Debian.
- `make install` respeitando `PREFIX` e `DESTDIR`.
- Fuzzing contínuo dos parsers, análise estática, revisão de privilégios (capabilities mínimas se viável).

**Aceite:**
- [ ] Pacote instala, sobe e substitui o OpenSnitch original sem migrar nenhum arquivo.

---

## 6. Estratégia de testes

| Nível | O quê | Precisa de root |
|---|---|---|
| Unitário | regras, parsers, durações, config, settings, framing gRPC | não |
| Diferencial | mesmo corpus no código Go e no C, saída comparada | não |
| Interop | combinações daemon/UI original × port | sim |
| Integração | netns com nftables, curl, resolver de teste | sim |
| Fuzzing | DNS, parse de pacote, JSON de regras, mensagens protobuf | não |
| Memória | todos os testes sob ASan/UBSan e `valgrind` no CI | — |

Os testes de integração rodam em `unshare`/netns e nunca alteram a rede do host. Rodar dentro de VM ou container privilegiado no CI.

**Matriz de interoperabilidade** (repetir a cada release):

| Daemon \ UI | UI original | Nossa UI |
|---|---|---|
| Daemon original | referência | Fase 6+ |
| Nosso daemon | Fase 5+ | Fase 6+ |

---

## 7. Acompanhando o upstream

### 7.1 Registro de sincronização

`docs/UPSTREAM.md` contém sempre:

```
Versão upstream sincronizada: vX.Y.Z
Commit: <hash>
Data do sync: AAAA-MM-DD
```

E uma tabela de mapeamento:

| Upstream | Port | Status |
|---|---|---|
| `daemon/rule/operator.go` | `daemon/rules/operator.c` | portado |
| `daemon/netfilter/queue.go` | `daemon/queue.c` | portado |
| `ui/opensnitch/dialogs/prompt/...` | `ui/prompt.c` | parcial |
| ... | ... | ... |

### 7.2 Procedimento de atualização

1. `cd upstream && git fetch --tags && git checkout <nova-tag>`.
2. `tools/upstream-diff.sh` lista os commits e arquivos alterados desde o hash registrado, agrupados por área: `daemon/`, `ui/`, `proto/`, `ebpf_prog/`, configs de exemplo.
3. Classificar cada mudança:
   - **Correção de bug** → portar com teste de regressão.
   - **Mudança de formato** (JSON de config/regras, `ui.proto`) → prioridade máxima; sem isso a interoperabilidade quebra. Rodar `tools/sync-proto.sh`.
   - **Funcionalidade nova** → abrir item no `docs/UPSTREAM.md` e planejar.
   - **Específica de Go/Python/Qt** (dependências, refatoração interna, build) → ignorar, registrar como "não aplicável".
   - **eBPF** → `tools/sync-ebpf.sh` e rodar os testes da Fase 9.
4. Portar em commits pequenos, um por mudança upstream, com mensagem `upstream: <hash curto> <título original>`.
5. Rodar todos os testes e a matriz de interoperabilidade contra a nova versão upstream.
6. Atualizar versão, hash e data no `docs/UPSTREAM.md`.

### 7.3 Versionamento

`<versão do port>+os<versão upstream>`, por exemplo `0.4.0+os1.7.0`. Deixa explícito com qual upstream o port é compatível.

### 7.4 Frequência

- Verificar o upstream a cada release dele, e mensalmente para correções de segurança.
- Mudanças em `ui.proto` ou formatos de arquivo têm prioridade sobre qualquer funcionalidade nova do port.

---

## 8. Manutenção

- **Política de código:** C11, sem extensões GNU obrigatórias, `-Wall -Wextra -Werror`, sem `strcpy`/`sprintf`, funções de parse sempre recebem tamanho do buffer.
- **Revisão de segurança** obrigatória em qualquer mudança em `daemon/queue.c`, `daemon/conn.c`, `daemon/dns/` e `common/grpc/`.
- **Benchmarks** em `docs/BENCH.md` atualizados a cada release; regressão de memória acima de 20% bloqueia release.
- **Issues** marcadas com `upstream` (vem do original) ou `port` (específica daqui).
- **Changelog** separando "sincronizado do upstream" e "específico do port".
- **Relatar ao upstream** bugs encontrados durante o port que também existam no código original.

---

## 9. Riscos conhecidos

| Risco | Mitigação |
|---|---|
| gRPC mínimo incompatível em casos de borda | testes de interop desde a Fase 5; capturar tráfego real entre daemon e UI originais como fixture |
| Diferença sutil de comportamento no motor de regras | testes diferenciais contra o código Go |
| Bugs de memória em código rodando como root | fuzzing, ASan no CI, revisão obrigatória dos parsers |
| Upstream muda formato de arquivo | sync de proto e fixtures automatizado; prioridade máxima |
| UI muito grande para portar de uma vez | checklist gerado dos `.ui` do upstream, portar aba por aba |

---

## 10. Modelo de `CLAUDE.md`

```markdown
# Projeto: port do OpenSnitch para C + GTK2

Leia docs/PORTING.md antes de qualquer tarefa. Fase atual: <N>.

## Regras
- Trabalhe em uma fase por vez. Não comece a fase seguinte com critério de aceite pendente.
- Antes de portar um módulo, leia o arquivo correspondente em upstream/ e atualize docs/UPSTREAM.md.
- Nunca invente campos de JSON, operandos, nomes de mensagens ou comportamento: confira no upstream.
- upstream/ é somente leitura. common/pb/ é gerado: não edite à mão.
- Escreva o teste antes ou junto com o código. `make test` e `make asan` precisam passar.
- C11, -Wall -Wextra -Werror, sem strcpy/sprintf, tamanho de buffer sempre explícito.
- Documente a posse de memória de cada struct no header.
- Testes de integração rodam só em netns; nunca altere a rede do host.

## Comandos
- make / make test / make asan / make fuzz
- sudo make test-integration
- tools/upstream-diff.sh
```

---

## 11. Como pedir cada etapa ao Claude Code

Sugestão de prompt por sessão:

> Estamos na Fase N do docs/PORTING.md. Leia os arquivos do upstream listados para esta fase, atualize o mapeamento em docs/UPSTREAM.md, implemente os módulos e os testes, e rode `make test` e `make asan`. Ao final, marque os critérios de aceite atendidos e liste o que ficou pendente.

Para sincronizar com o upstream:

> Rode tools/upstream-diff.sh, classifique cada mudança conforme a seção 7.2 do docs/PORTING.md e porte as que forem aplicáveis, uma por commit, com teste de regressão.
