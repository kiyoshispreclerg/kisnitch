# Kisnitch

[English](README.md) | **Português (Brasil)**

Uma versão leve do [OpenSnitch](https://github.com/evilsocket/opensnitch), o
firewall de aplicação para Linux, reescrita em C11 com interface em GTK2.

O objetivo é ser um substituto direto: mesmos arquivos de configuração e de
regras, e o mesmo protocolo gRPC entre daemon e interface. Assim o daemon do
Kisnitch funciona com a UI original e vice-versa.

> **Estado:** versão 0.1.0, fase 8 de 11 concluída. O daemon intercepta
> conexões (nfqueue + nftables, ou iptables), aplica as regras, acompanha o
> DNS, cuida do firewall de sistema (`system-fw.json`) e conversa com a UI
> original do OpenSnitch e com a nossa. A UI em GTK2 (`kisnitch-gtk`) está
> completa: popup de permissão, ícone de bandeja, janela de estatísticas,
> editor de regras, editor do firewall de sistema e preferências. Ainda faltam
> o monitor de processos eBPF (fase 9, opcional) e o restante (monitor audit,
> tarefas, TLS entre daemon e UI, i18n; fase 10). O plano completo está em
> [docs/PORTING.md](docs/PORTING.md).

## Instalação

Cada [release](https://github.com/kiyoshispreclerg/kisnitch/releases) traz
pacotes `.deb` (`amd64`) compilados para Ubuntu 22.04, Ubuntu 24.04, Devuan 5
daedalus e Devuan 6 excalibur. Baixe o do seu sistema e instale com o apt,
que traz as dependências:

```sh
sudo apt install ./kisnitch_<versão>-1_<sistema>_amd64.deb
```

O pacote instala `kisnitchd`, `kisnitch-gtk`, o arquivo `.desktop`, os
ícones e os metadados AppStream. Não precisa de systemd e conflita com
`opensnitch` e `python3-opensnitch-ui`, então remova-os antes. Cada pacote é
instalado e testado num sistema limpo do seu próprio alvo antes de ser
publicado. Releases que começam com `v0` são marcadas como pré-lançamento.

Para compilar do código-fonte, veja abaixo.

## Compilar e testar

Em Debian/Devuan/Ubuntu:

```sh
sudo apt install build-essential pkg-config libpcre2-dev \
    libnetfilter-queue-dev libnftnl-dev libmnl-dev \
    libnghttp2-dev libprotobuf-c-dev libgtk2.0-dev
make            # build/kisnitchd e build/kisnitch-gtk
make test       # testes unitários (sem root, sem rede)
make asan       # os mesmos testes com AddressSanitizer + UBSan
```

Testes de integração (precisam de `nftables`, `curl` e `python3`; os testes
com a UI falsa também de `python3-grpcio` e `python3-grpc-tools`, e os da
nossa UI de `xvfb` e `xdotool`; cada parte é pulada sem o que precisa). Rodam
num network namespace próprio e não mexem na rede da máquina:

```sh
sudo make test-integration   # ou sem sudo, se o kernel permitir user namespaces
```

Opcionais: `valgrind` (`make valgrind`), `cppcheck` (`make lint`) e `clang`
(`make fuzz-run`). Só quem muda `proto/ui.proto` precisa do
`protobuf-c-compiler` (`tools/sync-proto.sh` regenera `common/pb/`).

`make install` (e `make uninstall`) copia os binários, o `.desktop`, os
ícones e os metadados para `PREFIX` (padrão `/usr/local`), respeitando
`DESTDIR`; `tools/build-deb.sh` monta o `.deb` a partir da árvore atual. Os
comandos abaixo rodam direto de `build/`, sem instalar nada. O daemon usa os mesmos
arquivos do OpenSnitch (`/etc/opensnitchd/default-config.json` e
`/etc/opensnitchd/rules/`) e precisa de root. Pare o `opensnitchd` antes,
porque os dois usam a mesma fila e a mesma tabela do nftables:

```sh
sudo ./build/kisnitchd -debug -log-file /dev/stdout
```

A configuração e o estado do usuário (`default-config.json`, cada regra em
`rules/`, `settings.conf`) são gravados à prova de queda de energia: em
`<arquivo>.tmp`, com fsync e `rename`, depois de copiar a versão anterior para
`<arquivo>.backup`. Se um arquivo faltar ou vier vazio, o `.backup` é usado (com
aviso no log). Para resetar apagando um arquivo, apague também o `.backup`,
senão ele volta.

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

### A UI (`kisnitch-gtk`)

Substitui a `opensnitch-ui`: escuta no mesmo endereço (`unix:///tmp/osui.sock`,
ou `global/server_address` do `~/.config/opensnitch/settings.conf`, que é o
mesmo arquivo da UI original) e mostra o popup para cada conexão sem regra.
Feche a UI original antes (as duas usam o mesmo socket e o mesmo controle de
instância única):

```sh
./build/kisnitch-gtk                       # ou --socket unix:///outro/caminho
```

Funciona com o `opensnitchd` original e com o `kisnitchd`. O menu da
bandeja liga e desliga a interceptação e o início automático. A janela de
estatísticas, o editor de regras e a janela de preferências são os mesmos da UI
original e leem e gravam o mesmo `settings.conf` e usam um esquema SQLite compatível com o original.

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

O popup da UI também tem o seu: `make diff-ui` passa os mesmos casos pelo
código Python do popup original (com o Qt substituído) e pelo nosso. Precisa
do submódulo e de `python3-protobuf python3-grpc-tools python3-slugify
python3-unidecode`.

## Créditos e licença

O Kisnitch é obra derivada do OpenSnitch, criado por Simone Margaritelli
(evilsocket) e mantido por Gustavo Iñiguez Goia e colaboradores. Os arquivos
traduzidos do código original mantêm seus avisos de copyright.

Distribuído sob a [GNU GPL v3 ou posterior](LICENSE), a mesma licença do
OpenSnitch. O cJSON, em `common/vendor/cjson/`, é distribuído sob a licença MIT.
