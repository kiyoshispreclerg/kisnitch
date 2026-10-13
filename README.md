# Kisnitch

Uma versão leve do [OpenSnitch](https://github.com/evilsocket/opensnitch), o
firewall de aplicação para Linux, reescrita em C11 com interface em GTK2.

O objetivo é ser um substituto direto: mesmos arquivos de configuração e de
regras, e o mesmo protocolo gRPC entre daemon e interface. Assim o daemon do
Kisnitch funciona com a UI original e vice-versa.

> **Estado:** em desenvolvimento, fase 5: o daemon intercepta conexões
> (nfqueue + nftables), aplica as regras, acompanha o DNS e conversa com a UI
> original do OpenSnitch (perguntas, estatísticas, regras e configuração pela
> UI). A UI em GTK2 vem na fase 6. O plano completo está em
> [docs/PORTING.md](docs/PORTING.md).

## Compilar e testar

Em Debian/Devuan/Ubuntu:

```sh
sudo apt install build-essential pkg-config libpcre2-dev \
    libnetfilter-queue-dev libnftnl-dev libmnl-dev \
    libnghttp2-dev libprotobuf-c-dev
make            # build/kisnitchd
make test       # testes unitários (sem root, sem rede)
make asan       # os mesmos testes com AddressSanitizer + UBSan
```

Testes de integração (precisam de `nftables`, `curl` e `python3`; os testes
com UI também de `python3-grpcio` e `python3-grpc-tools`, e são pulados sem
eles). Rodam num network namespace próprio e não mexem na rede da máquina:

```sh
sudo make test-integration   # ou sem sudo, se o kernel permitir user namespaces
```

Opcionais: `valgrind` (`make valgrind`), `cppcheck` (`make lint`) e `clang`
(`make fuzz-run`). Só quem muda `proto/ui.proto` precisa do
`protobuf-c-compiler` (`tools/sync-proto.sh` regenera `common/pb/`).

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

### Com a UI original

A UI do OpenSnitch (`opensnitch-ui`) é o servidor: ela escuta em
`unix:///tmp/osui.sock` (o `Server.Address` do config padrão) e o daemon
conecta nela. Com a UI aberta na sessão gráfica:

```sh
sudo systemctl stop opensnitch     # ou o equivalente no seu init
sudo ./build/kisnitchd -debug -log-file /dev/stdout
```

O log mostra "Connected to the UI service on ..." e "Start receiving
notifications"; a partir daí, conexões sem regra abrem o popup da UI, e o
que se escolhe nela vira regra em `/etc/opensnitchd/rules/` (se a duração
for "sempre"). Para apontar para outro socket: `-ui-socket unix:///caminho`.
Autenticação TLS entre daemon e UI ainda não existe (fase 10).

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
