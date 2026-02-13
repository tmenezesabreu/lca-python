# LCA-Python-> Lula CNPJ Alfabetizado for Python

Ferramenta em Python para varrer múltiplos repositórios e detectar riscos de quebra na migração para CNPJ alfanumérico.

## Objetivo

Identificar padrões de código que tratam CNPJ como número ou validam apenas dígitos, priorizando os pontos com maior probabilidade de quebra.

## Pré-requisitos

- Python 3.10+ (recomendado 3.11+)
- `ripgrep` (`rg`) disponível no `PATH`

Instalação do `ripgrep`:

- Ubuntu/Debian: `sudo apt-get install ripgrep`
- macOS (Homebrew): `brew install ripgrep`
- Windows (Scoop): `scoop install ripgrep`

## Instalação

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Estrutura principal

- `checker.py`: varredura principal e geração de achados.
- `usage.py`: detecção heurística de símbolos CNPJ possivelmente não utilizados.
- `prioritize.py`: relatório acionável com priorização.
- `focus_breakage.py`: filtro focado apenas em risco de quebra em uso.
- `final_lists.py`: separa em "certeza quebra" e "possível quebra".

## Como usar

### 1) Rodar análise base

```bash
python3 checker.py \
  --base-dir /caminho/para/repositorios \
  --output-dir ./output
```

Para incluir `migracao-ensemble`:

```bash
python3 checker.py \
  --base-dir /caminho/para/repositorios \
  --output-dir ./output \
  --include-migracao-ensemble
```

### 2) Identificar símbolos CNPJ possivelmente não usados

```bash
python3 usage.py \
  --base-dir /caminho/para/repositorios \
  --out-dir ./output
```

### 3) Gerar priorização acionável

```bash
python3 prioritize.py \
  --findings-json ./output/findings.json \
  --out-dir ./output
```

### 4) Gerar relatório focado em quebra real

```bash
python3 focus_breakage.py \
  --findings-json ./output/findings.json \
  --unused-csv ./output/unused_cnpj_symbols.csv \
  --out-dir ./output
```

### 5) Gerar listas finais de remediação

```bash
python3 final_lists.py \
  --findings-json ./output/findings.json \
  --unused-csv ./output/unused_cnpj_symbols.csv \
  --out-dir ./output
```

## Saídas geradas

- `output/findings.json`: todos os achados detalhados.
- `output/findings.csv`: export tabular (`;` como separador).
- `output/summary.md`: resumo geral por severidade e repositório.
- `output/unused_cnpj_symbols.csv`: candidatos a símbolo CNPJ não utilizado.
- `output/actionable.md`: priorização por impacto.
- `output/focused_breakage_summary.md`: recorte focado em quebra provável.
- `output/lista_final_certeza_quebra.csv`: casos de maior certeza de quebra.
- `output/lista_final_possivel_quebra.csv`: casos possíveis para revisão.

## Regras detectadas (resumo)

- `numeric_type`: CNPJ modelado como tipo numérico.
- `numeric_parse`: CNPJ convertido para número.
- `digits_only_strict` / `digits_only_hint`: validações estritamente numéricas.
- `string_model`: CNPJ tratado como texto (sinal positivo).
- `cnpj_reference`: referência genérica a CNPJ.

## Publicação no GitHub

Checklist sugerido antes de abrir como público:

1. Validar se não há dados sensíveis em `output/` e `output_com_migracao/`.
2. Revisar nomes de pastas de entrada usadas em exemplos.
3. Criar repositório com nome sugerido: `lca-python-lula-cnpj-alfabetizado`.
4. Subir o conteúdo:

```bash
git init
git add .
git commit -m "chore: prepare public release for LCA-Python"
git branch -M main
git remote add origin <url-do-repo>
git push -u origin main
```

## Licença

Este projeto está licenciado sob MIT. Veja `LICENSE`.
