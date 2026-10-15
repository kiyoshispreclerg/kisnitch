# Projeto: Kisnitch, port do OpenSnitch para C + GTK2

Leia docs/PORTING.md antes de qualquer tarefa. Fase atual: 6 concluída. Próxima: 7.
(O teste diferencial opcional da fase 1 roda no job `diff` do CI ou com `make diff`
numa máquina com Go.)

## Regras
- Trabalhe em uma fase por vez. Não comece a fase seguinte com critério de aceite pendente.
- Antes de portar um módulo, leia o arquivo correspondente em upstream/ e atualize docs/UPSTREAM.md (tabela de mapeamento e, se houver, divergências).
- Nunca invente campos de JSON, operandos, nomes de mensagens ou comportamento: confira no upstream.
- upstream/ é somente leitura. common/pb/ é gerado: não edite à mão. common/vendor/ é código de terceiros: não edite.
- Escreva o teste antes ou junto com o código. `make test` e `make asan` precisam passar, com gcc e clang.
- C11, -Wall -Wextra -Werror, sem strcpy/sprintf, tamanho de buffer sempre explícito.
- Documente a posse de memória de cada struct no header.
- Testes de integração rodam só em netns; nunca altere a rede do host.
- Arquivos traduzidos do upstream mantêm o aviso de copyright original (ver cabeçalho de daemon/config.c).

## Convenções
- Prefixo `ks_` / `KS_` para símbolos públicos. Logging via `common/log.h` (`ks_info`, `ks_error`...).
- Binários: `kisnitchd` e `kisnitch-gtk`. Paths de config iguais aos do upstream.
- JSON com cJSON vendorizado (`common/vendor/cjson/`), helpers em `common/json_util.h`.
- Testes unitários: `tests/unit/test_*.c` (um binário por arquivo, `tests/harness.h`). Fixtures do upstream em `tests/fixtures/upstream/` (atualizar com tools/sync-fixtures.sh).
- Todo parser de entrada não confiável ganha alvo em `tests/fuzz/fuzz_*.c`; entradas que já quebraram algo ficam em `tests/fuzz/corpus/<alvo>/regress-*`.
- Comportamento do Go (encoding/json, regexp, net, strings) é reproduzido em common/ e daemon/rules/regex.c: use esses módulos, não equivalentes da libc.
- Divergências do upstream e bugs dele vão para docs/UPSTREAM.md.
- Netlink sem libmnl para sock_diag e o conector de processos (daemon/sockdiag.c, daemon/procmon/events.c); libmnl/libnftnl entram com o nftables (fase 3).
- gRPC próprio sobre nghttp2 em common/grpc/ (sem loop: o dono observa o fd e chama on_io/tick; serve ao daemon e à UI GLib). Mensagens com protobuf-c (common/pb/, gerado por tools/sync-proto.sh); mensagens a enviar são montadas numa arena (common/arena.h) e liberadas após o pack. Notas em docs/PROTOCOL.md.
- `Statistics.daemon_version` vai como a versão do upstream (KS_UPSTREAM_VERSION): a UI exige `x.y.z`.
- DNS sem dependência de systemd: o monitor do systemd-resolved (daemon/dns/resolved.c) fala varlink direto e só liga se o socket existir; o resto vem da fila do nfqueue, que funciona com qualquer resolvedor (Devuan incluído).
- Estado global de módulo é aceito onde o upstream usa globais (caches do procmon); APIs de teste para resetar (ks_procmon_cache_reset).
- Testes que inspecionam processos filhos via /proc são pulados sob valgrind (KS_TEST_VALGRIND): o filho de um processo sob valgrind é o próprio valgrind.
- UI: GTK 2 só em ui/prompt.c, ui/tray.c e ui/main.c; o resto de ui/ (libui.a) usa só GLib e é testado sem display (tests/unit/test_ui_*.c). Comportamento do Python/Qt (slugify, json.dumps, QSettings, configparser, LIKE do SQLite) é reproduzido em ui/: use esses módulos.
- A lógica do popup é comparada com o código Python do upstream por `make diff-ui`: mudou ui/prompt_rule.c ou ui/rulegen.c, rode-o.
- Recursos do upstream usados pela UI ficam em ui/res/ (tools/sync-ui-res.sh) e são embutidos no binário; as tabelas do slugify vêm de tools/gen-slug-tables.py.

## Comandos
- make / make test / make asan / make valgrind / make lint
- make diff (teste diferencial contra o Go do upstream; ver tests/diff/run.sh)
- make diff-ui (popup e editor de regras contra o código Python do upstream; precisa do submódulo e de python3-protobuf, python3-grpc-tools, python3-slugify, python3-unidecode)
- make fuzz-run FUZZ_TIME=60 (nesta máquina: `FUZZ_LDFLAGS=-L/usr/lib/gcc/x86_64-linux-gnu/11`)
- make test-integration (network namespace: como root usa `unshare -nm`; sem root, user namespace, se o kernel permitir. Precisa de nft, curl e python3; openssl para o teste HTTPS; python3-grpcio e python3-grpc-tools para os testes com UI (tests/integration/fake_ui.py). Os testes de DNS trocam /etc/resolv.conf só dentro do mount namespace. tests/integration/ui.sh roda a nossa UI em Xvfb (xdotool para o clique) com o nosso daemon e com o original, se OPENSNITCHD (padrão /usr/bin/opensnitchd) existir; tests/integration/stats_gui.sh roda tests/gui/test_stats_gui (diálogos e tarefas da janela de estatísticas com as respostas do daemon injetadas); tests/integration/stats_win.sh abre a janela de estatísticas com 100 mil eventos, e usa xsel e ImageMagick `import` se houver; KS_SHOT_DIR guarda capturas de tela)
- make install / install-data / uninstall (respeitam PREFIX e DESTDIR; `install-data` põe o .desktop, o ícone e o metainfo). tools/gen-icons.sh gera os PNG do ícone a partir do SVG (`data/`)
- tools/bench.sh [taxa] [segundos] (RSS do daemon ocioso e sob carga; resultados em docs/BENCH.md)
- tools/upstream-diff.sh, tools/sync-proto.sh, tools/sync-fixtures.sh
