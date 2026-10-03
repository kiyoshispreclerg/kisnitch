# Kisnitch

Uma versão leve do [OpenSnitch](https://github.com/evilsocket/opensnitch), o
firewall de aplicação para Linux, reescrita em C11 com interface em GTK2.

O objetivo é ser um substituto direto: mesmos arquivos de configuração e de
regras, e o mesmo protocolo gRPC entre daemon e interface. Assim o daemon do
Kisnitch funciona com a UI original e vice-versa.

> **Estado:** em desenvolvimento, fase 3: o daemon intercepta conexões
> (nfqueue + nftables) e aplica as regras; sem UI ainda, conexões sem regra
> recebem a `DefaultAction`. O plano completo está em [docs/PORTING.md](docs/PORTING.md).

## Compilar e testar

Em Debian/Devuan/Ubuntu:

```sh
sudo apt install build-essential pkg-config libpcre2-dev \
    libnetfilter-queue-dev libnftnl-dev libmnl-dev
make            # build/kisnitchd
make test       # testes unitários (sem root, sem rede)
make asan       # os mesmos testes com AddressSanitizer + UBSan
```

Testes de integração (precisam de `nftables`, `curl` e `python3`). Rodam num
network namespace próprio e não mexem na rede da máquina:

```sh
sudo make test-integration   # ou sem sudo, se o kernel permitir user namespaces
```

Opcionais: `valgrind` (`make valgrind`), `cppcheck` (`make lint`) e `clang`
(`make fuzz-run`).

Nada é instalado no sistema: tudo fica em `build/`. O daemon usa os mesmos
arquivos do OpenSnitch (`/etc/opensnitchd/default-config.json` e
`/etc/opensnitchd/rules/`) e precisa de root. Pare o `opensnitchd` antes,
porque os dois usam a mesma fila e a mesma tabela do nftables:

```sh
sudo ./build/kisnitchd -debug -log-file /dev/stdout
```

Ctrl+C remove as regras de interceptação. Para experimentar sem tocar na
rede da máquina, rode-o dentro de `sudo unshare -n` (é o que os testes de
integração fazem).

### Teste diferencial (opcional)

Compara o motor de regras com o código Go do próprio OpenSnitch, sobre o
corpus de `tests/diff/corpus.json`. Roda no job `diff` do CI; para rodar
localmente:

```sh
git submodule update --init          # código do upstream em upstream/
sudo apt install golang-go libnetfilter-queue-dev
make diff
```

Precisa de Go 1.21 ou mais novo (com rede na primeira vez, para baixar o
toolchain 1.23 que o upstream pede e os módulos Go).

## Créditos e licença

O Kisnitch é obra derivada do OpenSnitch, criado por Simone Margaritelli
(evilsocket) e mantido por Gustavo Iñiguez Goia e colaboradores. Os arquivos
traduzidos do código original mantêm seus avisos de copyright.

Distribuído sob a [GNU GPL v3 ou posterior](LICENSE), a mesma licença do
OpenSnitch. O cJSON, em `common/vendor/cjson/`, é distribuído sob a licença MIT.
