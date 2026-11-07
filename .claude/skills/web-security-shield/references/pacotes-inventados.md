# Pacotes inventados (slopsquatting) e typosquatting

**O que é:** a IA sugere `npm install` ou `pip install` de um pacote que **não existe** (nome "alucinado"). Atacantes monitoram esses nomes e publicam pacotes com esse nome contendo malware; ou registram nomes parecidos com os famosos (`expresss`, `reqeusts`). O código malicioso roda na instalação (`postinstall`) e rouba chaves, `.env` e tokens.

## Antes de instalar qualquer pacote sugerido por IA
1. **Existe e é o certo?** Abra `https://www.npmjs.com/package/NOME` ou `https://pypi.org/project/NOME/`.
2. **Sinais de alerta**: publicado há poucos dias/semanas, poucos downloads, sem repositório no GitHub, autor desconhecido, nome quase igual a um famoso, README vazio, scripts `preinstall/postinstall`.
3. **Prefira bibliotecas oficiais/documentadas** (a doc do Supabase manda usar `@supabase/supabase-js`, não `supabase-js-helper-pro`).
4. Rode o scanner com `--online`: ele consulta o npm/PyPI e marca pacote inexistente (CRÍTICO), muito novo (ALTO) e pouco usado (MÉDIO).

## Travar o que foi instalado
- Versões fixas + **lockfile commitado** (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`).
- Em CI: `npm ci` (respeita o lockfile), não `npm install`.
- `npm audit` / `pip-audit` / Dependabot / Renovate para vulnerabilidades conhecidas.
- Para instalar sem rodar scripts e revisar antes: `npm install --ignore-scripts`.

## Scripts de CDN (sites estáticos)
- Versão **exata** (`@2.45.4`), nunca `@latest` ou só `@2`.
- **SRI** (integrity), para o navegador recusar o arquivo se a CDN for comprometida:
  ```bash
  curl -s URL | openssl dgst -sha384 -binary | openssl base64 -A    # resultado vai em integrity="sha384-..."
  ```
  ```html
  <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/dist/umd/supabase.js"
          integrity="sha384-..." crossorigin="anonymous"></script>
  ```
- Só CDNs conhecidas (jsDelivr, cdnjs, unpkg) e liberadas na CSP.

## Se já instalou algo suspeito
Desinstale, apague `node_modules`, **troque todas as chaves** que estavam na máquina/projeto (`.env`, tokens do GitHub, npm, nuvem) e verifique o histórico de acessos dos serviços.
