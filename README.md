# 🛡️ Vota-i 2.0 — Suíte de Testes e Auditoria de Segurança

Repositório dedicado aos scripts experimentais de verificação, auditoria criptográfica, resistência a ataques e análise de conformidade de segurança do ecossistema de votação eletrônica **Vota-i 2.0** (`votaai-backend`, `votaai-desktop` e `projeto-react-native`).

Os ensaios estão organizados em **4 eixos de avaliação**, cobrindo desde regras de negócio e sigilo do voto na API até engenharia reversa de binários compilados e auditoria da cadeia de suprimentos.

---

## 📁 Estrutura do Repositório

```text
scriptsDeTesteVotai/
├── Eixo 1/
│   ├── prevencaoVotoDuplo.cpp              # Teste 1: Concorrência e prevenção de voto duplo (C++20 / OpenSSL 3.x)
│   ├── sigiloVoto.py                       # Teste 2: Auditoria de sigilo do voto na API e no banco de dados
│   └── maquinaEstados.py                   # Teste 3: Inviolabilidade da máquina de estados eleitoral
├── Eixo 2/
│   ├── resistenciaMitm.py                  # Teste 1 (Eixo 2): Resistência a MitM via Burp Suite e Certificate Pinning
│   ├── avaliacaoTrafegoPadding.py          # Teste 2 (Eixo 2): Análise de tráfego TLS e padding da cédula (Wireshark/tshark)
│   └── ancoragemChavesPinningFalso.py      # Teste 3 (Eixo 2): Ancoragem estática de chaves e simulação de Rogue API
├── Eixo 3/
│   ├── instrumentacaoFridaAntiDebugging.py # Teste 7: Instrumentação dinâmica (Frida), anti-debugging e anti-root
│   ├── engenhariaReversaGhidraOfuscacao.py # Teste 8: Engenharia reversa com Ghidra Headless e análise de ofuscação
│   └── armazenamentoPublicKeyPinning.py    # Teste 9: Inspeção de exposição de chaves de pinning em binários
└── Eixo 4/
    └── levantamentoBibliotecasModulos.py   # Teste 10: Inventário de dependências e consulta de vulnerabilidades (OSV/npm)
```

---

## 🧪 Descrição dos Eixos e Ensaios

### Eixo 1 — Integridade Eleitoral, Sigilo e Máquina de Estados
- **`Eixo 1/prevencaoVotoDuplo.cpp`**: Implementação nativa em **C++20** com paralelismo real (`std::thread`), sincronização por `std::barrier` e *Last-Byte Sync* (`TCP_NODELAY`) sobre sockets POSIX, utilizando OpenSSL 3.x para reproduzir as 3 camadas criptográficas do Vota-i 2.0 e testar rajadas concorrentes de submissão contra `/api/vote/cast/`.
- **`Eixo 1/sigiloVoto.py`**: Submete votos opcionais via `/api/vote/request/` e `/api/vote/cast/` e executa auditoria relacional, temporal e estocástica diretamente no banco de dados (PostgreSQL ou SQLite) e nos endpoints públicos da API para verificar a quebra de correlação entre eleitor e cédula.
- **`Eixo 1/maquinaEstados.py`**: Verifica o cumprimento estrito das transições `CREATED -> STARTED -> CLOSED -> TALLIED` na API diante de requisições fora de ordem, saltos prematuros, retrocessos de fase, adulteração de assinaturas, troca de máquina física e abuso de controle de acesso.

### Eixo 2 — Segurança de Rede, Tráfego e Ancoragem de Chaves
- **`Eixo 2/resistenciaMitm.py`**: Avalia os clientes `votaai-desktop` e `projeto-react-native` roteando o tráfego através de um proxy **Burp Suite** real com sua CA instalada na raiz de confiança, verificando o aborto imediato da conexão TLS diante de interceptação MitM.
- **`Eixo 2/avaliacaoTrafegoPadding.py`**: Captura tráfego TLS em arquivo PCAP e disseca os registros via **Wireshark (`tshark`)**, analisando estatisticamente (variância, correlações de Pearson/Spearman, Kruskal-Wallis, ANOVA, Entropia de Shannon e Informação Mútua) se o tamanho das requisições `POST /api/vote/cast/` vaza informação sobre a escolha do eleitor.
- **`Eixo 2/ancoragemChavesPinningFalso.py`**: Confronta os clientes Desktop e Mobile com uma API simulada adulterada (*Rogue API*) utilizando chaves distintas das ancoradas estaticamente, respostas em texto claro, tentativas de injeção de chave pública falsa e QR Codes com assinatura inválida.

### Eixo 3 — Blindagem de Binários, Engenharia Reversa e Anti-Depuração
- **`Eixo 3/instrumentacaoFridaAntiDebugging.py`**: Avalia a detecção em tempo de execução de depuradores (`gdb`, `lldb`, `TracerPid`, `strace`), `LD_PRELOAD`, *monkey-patching* em memória, root/Magisk e ganchos dinâmicos com **Frida** nos binários originais (`dist/votaai-desktop` e `app-release.apk` em dispositivo físico e emulador).
- **`Eixo 3/engenhariaReversaGhidraOfuscacao.py`**: Executa análise estática com **Ghidra Headless**, `readelf`, `dexdump`, disassembler CPython e inspeção Hermes HBC sobre `dist/votaai-desktop` e `app-release.apk`, avaliando remoção de símbolos, ofuscação R8/ProGuard, bytecode Hermes e manifesto criptográfico de integridade.
- **`Eixo 3/armazenamentoPublicKeyPinning.py`**: Inspeciona os artefatos compilados (ELF Desktop e APK Mobile — DEX, assets Hermes e `.so` nativas) em busca de chaves públicas, PEMs, blobs DER/SPKI ou hashes de pinning expostos em texto puro.

### Eixo 4 — Cadeia de Suprimentos e Dependências
- **`Eixo 4/levantamentoBibliotecasModulos.py`**: Inventaria as dependências dos projetos `votaai-backend`, `votaai-desktop` e `projeto-react-native`, consulta bases públicas de vulnerabilidades (**OSV** e **npm advisory**) e avalia controles básicos de menor privilégio e cadeia de suprimentos.

---

## 🚀 Pré-requisitos e Execução

### Ambiente Python
O repositório utiliza Python 3.12+ (com ambiente virtual `.venv` configurado):

```bash
source .venv/bin/activate
python "Eixo 1/maquinaEstados.py" --help
```

> **Nota:** Cada script possui opções de linha de comando próprias (como `--dry-run`, `--target`, `--base-url`, `--json-out`, entre outras). Execute com `--help` para visualizar todos os parâmetros suportados.

### Compilação e Execução do Teste em C++20 (`Eixo 1/prevencaoVotoDuplo.cpp`)
Requer compilador compatível com C++20 (`g++`) e bibliotecas de desenvolvimento do **OpenSSL 3.x** (`libssl`, `libcrypto`):

```bash
g++ -std=c++20 -O2 -Wall -pthread "Eixo 1/prevencaoVotoDuplo.cpp" -o "Eixo 1/prevencaoVotoDuplo" -lssl -lcrypto

# Validação local (dry-run) ou execução contra a API com token de votação:
"./Eixo 1/prevencaoVotoDuplo" --dry-run
"./Eixo 1/prevencaoVotoDuplo" <TOKEN_DE_VOTACAO>
```

### Ferramentas Auxiliares (conforme o eixo executado)
Dependendo do ensaio escolhido, os scripts interagem com ferramentas e artefatos externos esperados no ambiente:
- **Repositórios locais do ecossistema**: `votaai-backend`, `votaai-desktop` (incluindo `dist/votaai-desktop`) e `projeto-react-native` (incluindo `app-release.apk`);
- **Eixo 2**: Burp Suite + certificado CA (`burp-ca.crt`) e `tshark` (Wireshark CLI);
- **Eixo 3**: Ghidra (`analyzeHeadless`), `adb`, emulador Android / dispositivo físico, `frida` / `frida-server`, `gdb`, `lldb-server`, `readelf` e `dexdump`.

---

## 🤖 Declaração de Uso de Inteligência Artificial

Declaro que foram utilizadas ferramentas de inteligência artificial generativa (Gemini, desenvolvida pelo Google) durante o processo de elaboração deste repositório. A IA foi aplicada de forma restrita como assistente de produtividade na implementação do código, debugging de erros de sintaxe, tradução de textos e revisão textual. Ressalta-se que a especificação de requisitos, a lógica de programação, a arquitetura de software e a validação de todos os algoritmos gerados foram realizadas e supervisionadas integralmente, mantendo a autoria intelectual humana sobre a solução desenvolvida.
