# gRPC mínimo (daemon ↔ UI)

Implementação prevista na fase 5 (`common/grpc/`). Este arquivo reúne as notas
do protocolo à medida que forem levantadas.

- Definição: `proto/ui.proto`, copiado do upstream por `tools/sync-proto.sh`
  (versão atual: v1.8.0).
- Transporte: HTTP/2 (nghttp2) sobre socket Unix (`unix:///tmp/osui.sock`,
  também `unix-abstract:`) e TCP. Ver `getSocketPath` em
  `upstream/daemon/ui/config_utils.go`.
- Framing gRPC: 1 byte de compressão + 4 bytes de tamanho (big-endian) antes de
  cada mensagem; `content-type: application/grpc`; `grpc-status` nos trailers.
- Necessário: chamadas unárias e o stream bidirecional `Notifications`.
