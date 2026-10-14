# Medições

Metas do `docs/PORTING.md` (seção 1): daemon com RSS ocioso abaixo de 5 MB.
As medições são feitas com `tools/bench.sh [taxa] [segundos]`, que roda tudo
num network namespace próprio (como os testes de integração): o daemon com
uma regra `allow` para o python, um servidor TCP local que aceita e fecha, e
um cliente abrindo conexões novas na taxa pedida. Cada conexão é um SYN que
passa pela fila do nfqueue e pela busca do processo dono.

## Fase 3 (2026-10-03)

Máquina de desenvolvimento: Ubuntu 22.04, kernel 5.15.0-101, 16 CPUs, gcc 11
(`-O2 -g`), namespace sem root (`unshare -Urn`). Build `0.0.1+os1.8.0`.

| Situação | RSS |
|---|---|
| Ocioso (2 s após subir) | 1,3 MB |
| ~960 conexões/s por 10 s (meta: 1000/s) | pico 4,1 MB |
| ~1660 conexões/s por 10 s (pedido: 2000/s) | pico 5,3 MB |

```
$ tools/bench.sh 1000 10
RSS idle:                1284 KiB
load: target 1000/s for 10s -> 9620 connections (0 failed) in 10.01s = 961/s
RSS peak under load:     4108 KiB (VmHWM 4108 KiB)
RSS right after / +3s:   4108 / 4108 KiB
daemon CPU during load:  68% of one core

$ tools/bench.sh 2000 10
RSS idle:                1340 KiB
load: target 2000/s for 10s -> 16620 connections (0 failed) in 10.01s = 1660/s
RSS peak under load:     5348 KiB (VmHWM 5348 KiB)
daemon CPU during load:  94% of one core
```

Leitura:

- **Memória:** ocioso bem abaixo da meta. Sob carga o RSS sobe com os caches
  do monitor de processos (inodes e conexões já vistas, que expiram como no
  upstream) e com o heap que a glibc não devolve logo; não volta ao valor
  ocioso nos 3 s seguintes. A ~1000/s fica abaixo de 5 MB.
- **Vazão:** a ~1660 conexões/s o daemon satura um núcleo. A 1000/s o
  cliente (python, uma conexão por vez) ficou perto do alvo, com o daemon a
  68% de um núcleo.
- **Onde vai o tempo:** `strace -c` durante a carga mostra ~90% do tempo de
  sistema no `sendto` da consulta sock_diag (cerca de 640 µs por chamada).
  É a consulta do upstream (`GetSocketInfo`: dump de todos os sockets TCP
  filtrado pela porta de origem), e o kernel percorre todos os sockets,
  inclusive os milhares em TIME_WAIT que a própria carga cria. O upstream
  tem o mesmo custo. Uma consulta exata pela tupla (sem dump) seria O(1);
  fica como otimização futura, a fazer sem mudar o resultado da busca.
- **Veredicto síncrono:** o pacote é decidido no próprio loop. Não há o
  timeout de 1 ms do upstream que aceita o pacote sem avaliar quando os 16
  workers estão ocupados (ver divergências em `docs/UPSTREAM.md`).

## Fase 4 (2026-10-09)

Mesma máquina e build da fase 3, agora com o rastreamento de DNS.

```
$ tools/bench.sh 1000 10
RSS idle:                1308 KiB
load: target 1000/s for 10s -> 9930 connections (0 failed) in 10.01s = 992/s
RSS peak under load:     3764 KiB (VmHWM 3888 KiB)
RSS right after / +3s:   3888 / 3888 KiB
daemon CPU during load:  61% of one core
```

Sem regressão: a carga do bench não passa por DNS, e cada conexão só
ganha uma consulta ao cache (`HostOr`).

Cache de DNS (`daemon/dns/cache.c`, limite de 8192 entradas, divergência 31
em `docs/UPSTREAM.md`), medido com um programa que grava entradas IPv6 com
nomes de ~40 bytes (`host-N.some-cdn-provider.example.com`):

| Situação | RSS a mais |
|---|---|
| 8192 entradas | 1,8 MB |
| 16384 gravações (metade despejada) | 2,3 MB |

Com o cache cheio de nomes longos, o daemon ocioso fica perto de 3,5 MB,
ainda abaixo da meta de 5 MB. Nomes reais costumam ser mais curtos.

## Fase 5 (2026-10-13)

Mesma máquina. O daemon agora linka nghttp2 e protobuf-c, roda o cliente
da UI (poller de 1 s, reconexão) e conta estatísticas de cada conexão.

```
$ tools/bench.sh 1000 10        # sem UI (o daemon tenta conectar a cada segundo)
RSS idle:                2724 KiB
load: target 1000/s for 10s -> 9590 connections (0 failed) in 10.00s = 959/s
RSS peak under load:     4300 KiB (VmHWM 4300 KiB)
RSS right after / +3s:   4300 / 4300 KiB
daemon CPU during load:  69% of one core
```

| Ocioso | VmRSS | anônima | páginas de arquivo |
|---|---|---|---|
| fase 4 (mesmo método) | 1340 KiB | 160 KiB | 1156 KiB |
| fase 5, sem UI | 2724 KiB | 284 KiB | 2440 KiB |
| fase 5, UI conectada (`fake_ui.py`) | 2616 KiB | 284 KiB | 2332 KiB |

Quase todo o aumento do RSS ocioso é de páginas de arquivo: código das
bibliotecas (libnghttp2 ~100 KiB, libprotobuf-c ~40 KiB, o binário +100 KiB)
e mais páginas da libc tocadas. Essas páginas são compartilhadas com os outros
processos que usam as mesmas bibliotecas. A memória própria do daemon
(anônima) subiu 124 KiB. Sob carga, o pico subiu de 3888 para 4300 KiB:
as estatísticas guardam até 150 eventos (cópia da regra e referência ao
processo) entre um Ping e outro, como o upstream. Tudo abaixo da meta de
5 MB. A CPU sob carga subiu de 61% para 68-69% (duas execuções): cada
conexão agora também passa pelas estatísticas (mapas `By*` e cópia da regra
para o evento).

## Fase 6: UI (2026-10-14)

Mesma máquina, build `0.0.1+os1.8.0` (gcc 11, `-O2 -g`). `kisnitch-gtk` em
Xvfb (sem bandeja para embutir o ícone), tema GTK padrão, fontes do sistema.
Meta do `docs/PORTING.md`: UI ociosa (só bandeja) abaixo de 20 MB de RSS.

| Situação | RSS | Anônima | PSS |
|---|---|---|---|
| `kisnitch-gtk` ocioso, 3 s após subir | 27,6 MB | 5,0 MB | 7,7 MB |
| idem, sem `GTK_MODULES=gail:atk-bridge` | 25,6 MB | 4,7 MB | |
| depois de um popup, conectado ao daemon (`tests/integration/ui.sh`) | 40,7–41,9 MB | | |
| programa GTK 2 mínimo: só `gtk_init` e um `GtkStatusIcon` | 29,8 MB | 4,6 MB | |
| idem, sem `GTK_MODULES` | 27,0 MB | 4,3 MB | |
| UI original 1.6.5 (PyQt5) na sessão do usuário, para comparação | 140,8–222,2 MB | 57–85 MB | 75–110 MB |

Leitura:

- **A meta de 20 MB não é atingível com GTK 2 nesta máquina:** um programa
  GTK 2 vazio com um ícone de bandeja já ocupa 27–30 MB, quase tudo páginas
  de bibliotecas (GTK, GLib, cairo, pango, harfbuzz, X11) e do cache do
  fontconfig, compartilhadas com os outros programas GTK (o PSS da UI é
  7,7 MB). A parte própria da UI é a memória anônima: ~5 MB, quase igual à
  do programa vazio.
- **Depois do primeiro popup** o RSS sobe ~13 MB: glifos das fontes, o
  tema de ícones (o ícone do programa vem do tema) e as janelas realizadas.
- **Comparação:** cerca de 5 a 8 vezes menos que a UI Python original.

