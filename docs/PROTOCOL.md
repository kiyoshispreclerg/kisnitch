# gRPC mínimo (daemon ↔ UI)

Implementado na fase 5: transporte em `common/grpc/` (cliente e servidor
sobre nghttp2), mensagens em `common/pb/` (protobuf-c, gerado), conversões
em `daemon/protocol.c` e o lado do daemon em `daemon/uiclient.c`.

## Definição

- `proto/ui.proto`, copiado do upstream por `tools/sync-proto.sh` (v1.8.0).
  O script também regenera `common/pb/` com `protoc-c` (o código gerado fica
  versionado: quem só compila não precisa do `protoc-c`).
- Serviço `protocol.UI`, servidor é a UI e cliente é o daemon:

| RPC | Tipo | Prazo do cliente (upstream) | Quando |
|---|---|---|---|
| `Ping` | unária | 1 s | a cada segundo, só se houver eventos novos nas estatísticas |
| `AskRule` | unária | 120 s | conexão sem regra, UI conectada e sem outra pergunta pendente |
| `Subscribe` | unária | 10 s | ao conectar |
| `Notifications` | stream bidirecional | sem prazo | logo após o `Subscribe` |
| `PostAlert` | unária | 1 s | alertas (fila de 32 enquanto desconectado) |

## Transporte

- HTTP/2 em texto puro (h2c com conhecimento prévio: o cliente manda o
  prefácio direto, sem upgrade).
- Endereços (`Server.Address` no config ou `-ui-socket`), como
  `getSocketPath()`:
  - `unix:<caminho>`: o resto é o caminho, então `unix:///tmp/osui.sock` vira
    `///tmp/osui.sock` (equivalente a `/tmp/osui.sock`). Começando com `@`, é
    socket abstrato (convenção do Go).
  - `unix-abstract:<nome>`: socket abstrato (divergência 43 em
    `docs/UPSTREAM.md`).
  - qualquer outra coisa: `host:porta` em TCP. Endereços numéricos conectam
    direto; nomes são resolvidos numa thread, porque as consultas DNS do
    próprio daemon passam pela fila que o loop atende.
- Keepalive só em TCP, como o `keepalive.ClientParameters` do upstream: após
  5 s sem receber nada, um PING; sem resposta em 22 s, a conexão cai. A UI
  também manda PINGs (5 s / 20 s, `grpc.keepalive_*` em `ui/bin/opensnitch-ui`)
  e o nghttp2 responde sozinho.
- "Conectado" (`connectivity.Ready` do grpc-go) é ter recebido o SETTINGS do
  servidor.
- Reconexão: o poller roda a cada segundo; se não está conectado, tenta de
  novo. Uma conexão que caiu só é percebida pelo poller (log "Connection to
  the UI service lost."), igual ao upstream.

## Framing e cabeçalhos

- Cada mensagem: 1 byte de compressão (sempre 0) + 4 bytes de tamanho
  (big-endian) + a mensagem protobuf.
- Requisição: `:method POST`, `:scheme http`, `:path /protocol.UI/<Método>`,
  `:authority` (`localhost` em socket Unix, `host:porta` em TCP),
  `content-type: application/grpc`, `te: trailers`, `user-agent` e, com
  prazo, `grpc-timeout` (até 8 dígitos e a unidade mais fina que couber,
  como o grpc-go: `1000000u`, `120000m`).
- Sem compressão: não mandamos `grpc-accept-encoding`, então o servidor não
  comprime; mensagem com o bit de compressão é erro (`Internal`). O
  `PostAlert` do upstream usa gzip; aqui vai sem (divergência 38).
- Resposta: `:status 200`, `content-type: application/grpc`, mensagens, e
  trailers com `grpc-status` e `grpc-message` (percent-encoded). Resposta
  "trailers-only" (só um HEADERS com END_STREAM e o status) é aceita: é o
  que o grpcio do Python manda quando o handler devolve `None` ou levanta
  exceção (a UI faz isso no `AskRule` em erro).
- Limite de mensagem recebida: 4 MiB (padrão do gRPC), acima disso
  `ResourceExhausted`.
- Status sem trailers: RST_STREAM CANCEL → `Canceled`, REFUSED_STREAM →
  `Unavailable`, outro código → `Internal`; HTTP diferente de 200 é mapeado
  como na especificação (404 → `Unimplemented`, 503 → `Unavailable`...).
- Os erros aparecem no log no formato do grpc-go:
  `rpc error: code = DeadlineExceeded desc = context deadline exceeded`.

## Mensagens

- proto3 exige UTF-8 válido em `string`: o Go recusa montar ou ler mensagem
  com UTF-8 inválido. O port verifica as duas pontas
  (`ks_pb_valid_utf8()`): um processo com argumento em Latin-1, por
  exemplo, faz o `AskRule` falhar e a conexão recebe a ação padrão, como no
  upstream.
- `Statistics.daemon_version` é a versão do upstream (`1.8.0`), não a do
  port: a UI faz `daemon_version.split(".")` esperando três partes, e o
  `Ping` dela descartaria as estatísticas com `0.0.1+os1.8.0`.
- `ClientConfig` (Subscribe): `config` é o arquivo de config cru, sem as
  quebras de linha; `name` e `version` vêm de
  `/proc/sys/kernel/{hostname,osrelease}`; `id` é o `UnixNano()` de um
  `time.Time` zerado no Go (11651379494838206464, por overflow); `rules`
  são todas as regras carregadas; `systemFirewall` fica vazio até a fase 8.
  Da resposta, o daemon só usa o `DefaultAction` do `config` devolvido: é
  a ação padrão enquanto a UI está conectada (`deny` até a UI dizer outra
  coisa).
- `Notifications`: o daemon abre o stream e manda primeiro um
  `NotificationReply{id: 0, code: OK}`. Cada `Notification` recebida é
  respondida com `NotificationReply{id: <id da notificação>}`, `code ERROR`
  e a mensagem em `data` em caso de erro. `type` `NONE` (ou menor) fecha o
  canal e desconecta, e o poller reconecta. Ações:

| Ação | Tratamento | Resposta |
|---|---|---|
| `CHANGE_CONFIG` | aplica `data` como config (`reloadConfiguration`) e grava o arquivo; o inotify recarrega de novo em seguida, como no upstream | OK / erro |
| `ENABLE_RULE`, `DISABLE_RULE` | `Replace` de cada regra com `enabled` ajustado; grava se `always` | OK / erro da última |
| `CHANGE_RULE` | `Replace` (cria ou troca) | OK / erro |
| `DELETE_RULE` | `Delete` pelo nome; `always` sai do disco | OK / erro da última |
| `ENABLE_INTERCEPTION` | reconfigura o monitor de processos e liga as regras de interceptação | OK / erro |
| `DISABLE_INTERCEPTION` | para o monitor e tira as regras | OK / erro |
| `RELOAD_FW_RULES` | regras de sistema: fase 8 | erro |
| `TASK_START`, `TASK_STOP` | JSON `{"Name", "Data"}`; tarefas conhecidas (`pid-monitor`, `node-monitor`, `sockets-monitor`): fase 10 | erro no start; nada no stop; desconhecidas: nada |
| `LOG_LEVEL`, `STOP` | ignoradas (o upstream também não trata) | nenhuma |

## Pergunta à UI (AskRule)

O upstream reenfileira o pacote na fila `N+1` só para a goroutine poder
esperar a resposta sem travar a fila principal. Aqui o veredicto do pacote
fica pendente (o kernel aceita veredictos fora de ordem pelo id) e sai
quando a UI responde, quando o prazo de 120 s vence ou quando a conexão cai
(nesses dois casos, ação padrão). Como no upstream:

- só uma pergunta por vez; enquanto ela está pendente, outras conexões sem
  regra recebem a ação padrão (a da UI, porque está conectada) e as que têm
  regra seguem normalmente;
- a regra respondida entra no loader (`Add`), e é gravada em disco se a
  duração for `always`; `once` não fica;
- o veredicto usa a regra recebida, mesmo que ela não compile.

O prazo de resposta que o usuário configura fica na UI (contagem do popup).
Ao estourar, a UI responde com a ação padrão dela, e o daemon trata como
qualquer resposta.

## Testes

- `tests/unit/test_grpc.c`: nosso cliente contra nosso servidor
  (`socketpair`): unária, stream, trailers-only, prazo, limite de tamanho,
  queda, keepalive, lixo na conexão.
- `tests/unit/test_uiclient.c`: o cliente do daemon contra uma UI falsa
  feita com o nosso servidor: Subscribe, todas as ações de notificação, Ping
  com estatísticas, AskRule (resposta, erro, queda), alertas e reconexão.
- `tests/integration/run.sh` (seção 6): o daemon de verdade num netns contra
  `tests/integration/fake_ui.py` (grpcio do Python, mesmas opções de
  servidor da UI real).
- `tests/fuzz/fuzz_grpc.c`, `fuzz_notification.c`: bytes arbitrários na
  conexão (como cliente e como servidor) e mensagens arbitrárias da UI. As
  sementes de `fuzz_grpc` são tráfego real gravado entre grpcio e grpcio.
- Interoperabilidade com a UI original: ver a fase 5 em `docs/PORTING.md`.
