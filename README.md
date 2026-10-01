# Kisnitch

Uma versão leve do [OpenSnitch](https://github.com/evilsocket/opensnitch), o
firewall de aplicação para Linux, reescrita em C11 com interface em GTK2.

O objetivo é ser um substituto direto: mesmos arquivos de configuração e de
regras, e o mesmo protocolo gRPC entre daemon e interface. Assim o daemon do
Kisnitch funciona com a UI original e vice-versa.

> **Estado:** em desenvolvimento, fase 0 (fundação). Ainda não intercepta
> conexões. O plano completo está em [docs/PORTING.md](docs/PORTING.md).

## Compilar

Requer apenas `gcc` ou `clang`, `make` e `pkg-config`.

```sh
make            # build/kisnitchd
make test       # testes unitários
make asan       # testes com AddressSanitizer + UBSan
```

## Créditos e licença

O Kisnitch é obra derivada do OpenSnitch, criado por Simone Margaritelli
(evilsocket) e mantido por Gustavo Iñiguez Goia e colaboradores. Os arquivos
traduzidos do código original mantêm seus avisos de copyright.

Distribuído sob a [GNU GPL v3 ou posterior](LICENSE), a mesma licença do
OpenSnitch. O cJSON, em `common/vendor/cjson/`, é distribuído sob a licença MIT.
