# Projeto: Kisnitch, port do OpenSnitch para C + GTK2

Leia docs/PORTING.md antes de qualquer tarefa. Fase atual: 0.

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
- Todo parser de entrada não confiável ganha alvo em `tests/fuzz/fuzz_*.c`.

## Comandos
- make / make test / make asan / make valgrind / make lint
- make fuzz-run FUZZ_TIME=60 (nesta máquina: `FUZZ_LDFLAGS=-L/usr/lib/gcc/x86_64-linux-gnu/11`)
- sudo make test-integration (a partir da fase 3)
- tools/upstream-diff.sh, tools/sync-proto.sh, tools/sync-fixtures.sh
