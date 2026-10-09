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
