#!/usr/bin/env python3
"""
security_scan.py - scanner de seguranca para sites e apps web (sem dependencias).

Procura, por analise estatica, os erros mais comuns em sites feitos com IA:
  1. Chaves de API expostas (service_role do Supabase, Stripe, OpenAI, AWS...)
  2. XSS (innerHTML/dangerouslySetInnerHTML/v-html/eval com dado do usuario)
  3. SQL injection (SQL montado com concatenacao ou template string)
  4. Banco aberto (tabela Supabase sem RLS, policy "using (true)" para escrita,
     security definer sem search_path)
  5. Rotas de API expostas (sem checagem de login / CORS aberto)
  6. Sem limite de tentativas (rotas e login sem rate limit / captcha)
  7. Prompt injection (entrada do usuario no prompt de sistema, saida do
     modelo no HTML, ferramentas perigosas)
  8. Pacotes inventados / typosquatting (com --online consulta npm e PyPI)
  9. Cabecalhos de seguranca (CSP, HSTS, nosniff...) e arquivos sensiveis publicados

E heuristico: encontra o que PRECISA DE REVISAO, nao prova que o site e seguro.
Uso:
  python3 security_scan.py <pasta> [--online] [--json] [--fail-on high|critical|medium|none]
Codigo de saida: 1 se houver achado com severidade >= --fail-on (padrao: high).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

SEVERIDADES = ["critical", "high", "medium", "low", "info"]
ROTULO = {"critical": "CRITICO", "high": "ALTO", "medium": "MEDIO", "low": "BAIXO", "info": "INFO"}

PULAR_PASTAS = {"node_modules", ".git", "dist", "build", ".next", ".nuxt", ".svelte-kit", ".vercel",
                ".netlify", "vendor", "__pycache__", ".venv", "venv", "coverage", ".turbo", ".cache"}
EXT_CODIGO = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro", ".html", ".htm",
              ".py", ".php", ".rb", ".go", ".java", ".kt", ".cs", ".rs"}
EXT_TEXTO = EXT_CODIGO | {".sql", ".json", ".toml", ".yml", ".yaml", ".env", ".txt", ".md", ".cfg", ".ini", ".xml"}
MAX_BYTES = 1_500_000


@dataclass
class Achado:
    severidade: str
    categoria: str
    arquivo: str
    linha: int
    mensagem: str
    correcao: str
    trecho: str = ""


ACHADOS: list[Achado] = []


def add(sev, cat, arq, linha, msg, fix, trecho=""):
    trecho = (trecho or "").strip()
    if len(trecho) > 140:
        trecho = trecho[:137] + "..."
    ACHADOS.append(Achado(sev, cat, arq, linha, msg, fix, mascarar(trecho)))


def mascarar(t: str) -> str:
    """Nunca imprime um segredo inteiro no relatorio."""
    def m(mo):
        s = mo.group(0)
        return s[:6] + "…" + s[-4:] if len(s) > 14 else "…"
    return re.sub(r"[A-Za-z0-9_\-]{24,}(?:\.[A-Za-z0-9_\-]{10,}){0,2}", m, t)


def linha_de(texto: str, pos: int) -> int:
    return texto.count("\n", 0, pos) + 1


def linha_txt(texto: str, n: int) -> str:
    ls = texto.splitlines()
    return ls[n - 1] if 0 < n <= len(ls) else ""


# ---------------------------------------------------------------------------
# 1. SEGREDOS
# ---------------------------------------------------------------------------
PADROES_SEGREDO = [
    (r"sb_secret_[A-Za-z0-9_\-]{20,}", "critical", "Chave SECRETA do Supabase (sb_secret_) exposta"),
    (r"sk_live_[0-9A-Za-z]{20,}", "critical", "Chave secreta do Stripe (sk_live_) exposta"),
    (r"rk_live_[0-9A-Za-z]{20,}", "critical", "Chave restrita do Stripe (rk_live_) exposta"),
    (r"sk-ant-[A-Za-z0-9_\-]{30,}", "critical", "Chave da API da Anthropic exposta"),
    (r"sk-(?:proj-)?[A-Za-z0-9_\-]{40,}", "critical", "Chave da API da OpenAI exposta"),
    (r"AKIA[0-9A-Z]{16}", "critical", "Chave de acesso da AWS exposta"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----", "critical", "Chave privada exposta"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}", "critical", "Token do GitHub exposto"),
    (r"xox[baprs]-[A-Za-z0-9-]{20,}", "high", "Token do Slack exposto"),
    (r"AIza[0-9A-Za-z_\-]{35}", "medium", "Chave do Google (AIza...) - confirme se tem restricao de dominio/API"),
    (r"APP_USR-\d{8,}-\d{6}-[0-9a-f]{32}-\d{6,}", "critical", "Access token do Mercado Pago exposto"),
    (r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", "critical", "Chave do SendGrid exposta"),
    (r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s:'\"]+:[^\s@'\"]+@[^\s'\"]+", "critical",
     "String de conexao com senha do banco exposta"),
]
GENERICO = re.compile(
    r"""(?i)\b(api[_-]?key|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|senha|private[_-]?key)\b["']?\s*[:=]\s*["']([^"'\s]{12,})["']""")
JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
ENV_PUBLICO = re.compile(r"\b(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_)[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|SK_|OPENAI|ANTHROPIC)[A-Z0-9_]*")


def b64json(seg: str):
    try:
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg.encode()).decode("utf-8", "ignore"))
    except Exception:
        return None


def scan_segredos(rel: str, txt: str):
    ext = os.path.splitext(rel)[1].lower()
    if ext == ".md":
        return
    for pad, sev, msg in PADROES_SEGREDO:
        for mo in re.finditer(pad, txt):
            add(sev, "chave-exposta", rel, linha_de(txt, mo.start()), msg,
                "Apague a chave do codigo, GERE UMA NOVA no painel do servico (a antiga ja vazou) e guarde-a "
                "em variavel de ambiente do servidor (Netlify > Environment variables / Supabase Edge Function secrets).",
                linha_txt(txt, linha_de(txt, mo.start())))
    for mo in JWT.finditer(txt):
        payload = b64json(mo.group(0).split(".")[1]) or {}
        role = str(payload.get("role", ""))
        n = linha_de(txt, mo.start())
        if role == "service_role":
            add("critical", "chave-exposta", rel, n, "Chave service_role do Supabase exposta (ignora TODAS as regras RLS)",
                "Troque por SUPABASE_ANON_KEY no front-end. Gere nova service_role em Supabase > Settings > API "
                "(JWT secret / rotate) e use-a so em Edge Functions ou servidor.", linha_txt(txt, n))
        elif role == "anon":
            add("info", "chave-exposta", rel, n, "Chave anon do Supabase no codigo (e publica por natureza)",
                "Tudo bem ficar no front-end DESDE QUE todas as tabelas tenham RLS ativo e politicas corretas.")
        elif payload:
            add("medium", "chave-exposta", rel, n, "Token JWT fixo no codigo",
                "Tokens nao devem ficar no codigo. Confirme se e de teste e remova.", linha_txt(txt, n))
    if ext not in {".json"} and not rel.endswith(".lock"):
        for mo in GENERICO.finditer(txt):
            valor = mo.group(2)
            if re.fullmatch(r"(?i)(x+|\*+|your[_-].*|seu[_-].*|example.*|changeme|placeholder.*|<.*>|\$\{.*\}|process\.env.*)", valor) \
                    or re.fullmatch(r"[a-z]+(-[a-z]+)*", valor):
                continue
            n = linha_de(txt, mo.start())
            add("medium", "chave-exposta", rel, n, f"Possivel segredo fixo em '{mo.group(1)}'",
                "Mova para variavel de ambiente no servidor; nunca no codigo que vai para o navegador.", linha_txt(txt, n))
    for mo in ENV_PUBLICO.finditer(txt):
        n = linha_de(txt, mo.start())
        add("high", "chave-exposta", rel, n, f"Variavel '{mo.group(0)}' tem prefixo PUBLICO mas nome de segredo",
            "Prefixos NEXT_PUBLIC_/VITE_/REACT_APP_ vao para o navegador. Tire o prefixo e use so no servidor.", linha_txt(txt, n))


# ---------------------------------------------------------------------------
# 2. XSS
# ---------------------------------------------------------------------------
SINK_HTML = re.compile(r"\.(innerHTML|outerHTML)\s*\+?=|insertAdjacentHTML\s*\(|document\.write(ln)?\s*\(")
ESCAPES = re.compile(r"^\s*(esc|escape|escapeHtml|escapeHTML|sanitize|DOMPurify\.sanitize|he\.encode|encodeURIComponent|"
                     r"Number|parseInt|parseFloat|Math\.|String\(Number|fmt|moeda|JSON\.stringify|ic|icon)\b")
DADO_USUARIO = re.compile(r"(?i)\b(nome|name|titulo|title|descricao|description|desc|coment|comment|mensagem|message|msg|"
                          r"email|bio|texto|text|query|search|busca|q|input|value|valor|endereco|address|user|usuario|"
                          r"conteudo|content|html|body|params|searchParams|location\.(hash|search)|data)\b")
FONTE_EXTERNA = re.compile(r"(location\.|searchParams|URLSearchParams|params\.|req\.|request\.|\.value\b|body\.|query\.|"
                           r"\bdata\.|response\.|res\.data|json\.|payload|message\.content|completion|choices\[)")


def scan_xss(rel: str, txt: str):
    linhas = txt.splitlines()
    tem_esc = bool(re.search(r"function\s+(esc|escape|escapeHtml)\b|const\s+(esc|escape|escapeHtml)\s*=|DOMPurify", txt))
    for i, l in enumerate(linhas, 1):
        if re.search(r"\beval\s*\(|new\s+Function\s*\(|set(Timeout|Interval)\s*\(\s*[\"'`]", l) and not l.strip().startswith(("//", "#", "*")):
            add("high", "xss", rel, i, "eval/new Function/setTimeout com texto executa codigo arbitrario",
                "Remova eval. Use JSON.parse para dados e funcoes normais em vez de strings.", l)
        if "dangerouslySetInnerHTML" in l and "DOMPurify" not in l and "sanitize" not in l:
            add("medium", "xss", rel, i, "dangerouslySetInnerHTML sem sanitizacao visivel",
                "Renderize como texto ({valor}) ou passe por DOMPurify.sanitize() antes.", l)
        if re.search(r"\bv-html\s*=|\{@html\s", l):
            add("medium", "xss", rel, i, "v-html / {@html} renderiza HTML cru",
                "Use interpolacao normal ({{ }} / { }) ou sanitize com DOMPurify.", l)
        if re.search(r"""href\s*=\s*["'`]?\s*javascript:""", l, re.I):
            add("medium", "xss", rel, i, "Link com javascript:", "Use onclick/addEventListener; nunca javascript: em href.", l)
        if re.search(r'target\s*=\s*["\']_blank["\']', l) and "noopener" not in l and "noreferrer" not in l:
            add("low", "xss", rel, i, "target=_blank sem rel=noopener", 'Adicione rel="noopener noreferrer".', l)
    # Interpolacoes ${...} em HTML montado como texto
    if SINK_HTML.search(txt):
        if not tem_esc:
            mo = SINK_HTML.search(txt)
            add("medium", "xss", rel, linha_de(txt, mo.start()),
                "HTML montado com innerHTML/insertAdjacentHTML e nenhuma funcao de escape no arquivo",
                "Crie esc() que troca & < > \" ' por entidades e use em TODO dado vindo do usuario/banco, "
                "ou use textContent / createElement.", linha_txt(txt, linha_de(txt, mo.start())))
        revisar = []
        for i, l in enumerate(linhas, 1):
            if "${" not in l or "<" not in l:
                continue
            for expr in re.findall(r"\$\{([^{}]{1,120})\}", l):
                e = expr.strip()
                if ESCAPES.match(e) or "esc(" in e or "escape" in e or "sanitize" in e:
                    continue
                if re.search(r"[\"'`]", e):   # ternarios com texto fixo: nao e dado externo
                    continue
                if FONTE_EXTERNA.search(e):
                    add("medium", "xss", rel, i, f"Dado externo inserido no HTML sem escape: ${{{e[:50]}}}",
                        "Envolva com esc(...) (ou use textContent). Dados de URL, formulario, banco e IA podem conter <script>.", l)
                elif DADO_USUARIO.search(e):
                    revisar.append(i)
        if revisar:
            add("low", "xss", rel, revisar[0], f"{len(revisar)} interpolacao(oes) em HTML para revisar (linhas {', '.join(map(str, revisar[:8]))}{'...' if len(revisar) > 8 else ''})",
                "Confira se cada valor e constante do proprio codigo. Se vier do usuario/banco, use esc(...).")


# ---------------------------------------------------------------------------
# 3. SQL INJECTION
# ---------------------------------------------------------------------------
SQL_PALAVRA = r"(?:\bSELECT\b[^;]*?\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\s+[\w.\"]+\s+SET\b|\bDELETE\s+FROM\b|\bDROP\s+TABLE\b|\bWHERE\s+\w+\s*(=|LIKE|IN)\b)"


def scan_sqli(rel: str, txt: str):
    ext = os.path.splitext(rel)[1].lower()
    linhas = txt.splitlines()
    for i, l in enumerate(linhas, 1):
        s = l.strip()
        if s.startswith(("//", "#", "--", "*")):
            continue
        if re.search(rf"[`].*{SQL_PALAVRA}.*\$\{{", l, re.I) and re.search(r"(query|execute|exec|raw|sql|prepare|unsafe)", l, re.I):
            add("high", "sql-injection", rel, i, "SQL montado com template string ${...}",
                "Use parametros: db.query('... WHERE id = $1', [id]) / sql`... ${id}` de bibliotecas que parametrizam "
                "(postgres.js, Prisma $queryRaw com tagged template).", l)
        elif re.search(rf"[\"'].*{SQL_PALAVRA}.*[\"']\s*\+\s*[\w(]", l, re.I):
            add("high", "sql-injection", rel, i, "SQL concatenado com +", "Use consulta parametrizada (placeholders $1, ?, :nome).", l)
        if ext == ".py" and re.search(r"(execute|executemany|raw)\s*\(\s*f[\"']", l):
            add("high", "sql-injection", rel, i, "SQL com f-string no Python", "Use cursor.execute('... %s', (valor,)).", l)
        if ext == ".py" and re.search(r"(execute|raw)\s*\(\s*[\"'].*%s.*[\"']\s*%\s*", l):
            add("high", "sql-injection", rel, i, "SQL formatado com % no Python", "Passe os valores como 2o argumento do execute.", l)
        if ext == ".php" and re.search(r"(mysqli_query|->query)\s*\(.*\$_(GET|POST|REQUEST)", l):
            add("critical", "sql-injection", rel, i, "Entrada do usuario direto no SQL (PHP)", "Use PDO com prepare/execute.", l)
        if re.search(r"\.(or|filter|textSearch)\s*\(\s*`[^`]*\$\{", l):
            add("medium", "sql-injection", rel, i, "Filtro do Supabase/PostgREST montado com texto do usuario",
                "Valide/escape o valor (remova , ( ) . *) ou use .eq/.ilike com o valor separado.", l)
    if ext == ".sql":
        for mo in re.finditer(r"(?is)execute\s+(?!format\s*\(\s*'[^']*%[IL])[^;]*\|\|", txt):
            n = linha_de(txt, mo.start())
            add("high", "sql-injection", rel, n, "EXECUTE com SQL concatenado (||) dentro de funcao",
                "Use EXECUTE format('... %I ... %L', ident, valor) ou EXECUTE ... USING.", linha_txt(txt, n))


# ---------------------------------------------------------------------------
# 4. BANCO ABERTO (Supabase / Postgres)
# ---------------------------------------------------------------------------
def dividir_sql(txt: str):
    """Divide SQL em comandos respeitando $$...$$ e strings."""
    out, buf, i, n = [], [], 0, len(txt)
    dollar = None
    inicio = 0
    while i < n:
        c = txt[i]
        if dollar:
            if txt.startswith(dollar, i):
                buf.append(dollar); i += len(dollar); dollar = None; continue
            buf.append(c); i += 1; continue
        if c == "-" and txt.startswith("--", i):
            j = txt.find("\n", i)
            j = n if j < 0 else j
            buf.append(" " * (j - i)); i = j; continue
        if c == "$":
            mo = re.match(r"\$[A-Za-z_]*\$", txt[i:])
            if mo:
                dollar = mo.group(0); buf.append(dollar); i += len(dollar); continue
        if c == "'":
            j = i + 1
            while j < n:
                if txt[j] == "'" and not txt.startswith("''", j):
                    break
                j += 2 if txt.startswith("''", j) else 1
            buf.append(txt[i:j + 1]); i = j + 1; continue
        if c == ";":
            out.append(("".join(buf), inicio)); buf = []; i += 1; inicio = i; continue
        buf.append(c); i += 1
    if "".join(buf).strip():
        out.append(("".join(buf), inicio))
    return out


def scan_sql_banco(rel: str, txt: str):
    cmds = dividir_sql(txt)
    tabelas, rls = {}, set()
    for c, pos in cmds:
        s = " ".join(c.split())
        n = linha_de(txt, pos + (len(c) - len(c.lstrip())))
        mo = re.search(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?([\w.\"]+)", s)
        if mo:
            nome = mo.group(1).replace('"', "").lower()
            if not nome.startswith(("auth.", "storage.", "pg_", "temp")):
                tabelas[nome if "." in nome else "public." + nome] = n
        mo = re.search(r"(?i)alter\s+table\s+(?:only\s+)?([\w.\"]+)\s+enable\s+row\s+level\s+security", s)
        if mo:
            nome = mo.group(1).replace('"', "").lower()
            rls.add(nome if "." in nome else "public." + nome)
        mo = re.search(r"(?i)create\s+policy\s+.+?\s+on\s+([\w.\"]+)(.*)", s)
        if mo:
            corpo = mo.group(2).lower()
            cmd = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", corpo)
            cmd = cmd.group(1) if cmd else "all"
            aberto = re.search(r"\b(using|with\s+check)\s*\(\s*true\s*\)", corpo)
            if aberto and cmd != "select":
                add("high", "banco-aberto", rel, n, f"Politica '{cmd}' com (true): qualquer pessoa pode escrever/apagar",
                    "Restrinja: using (dono = auth.uid()) / with check (dono = auth.uid()) ou a uma funcao is_admin().", s[:140])
            elif aberto:
                add("info", "banco-aberto", rel, n, "Leitura publica (select using true)",
                    "Ok so se TODAS as colunas dessa tabela puderem ser publicas (nada de e-mail, telefone, CPF).", s[:140])
            if re.search(r"\bto\s+anon\b", corpo) and cmd != "select":
                add("high", "banco-aberto", rel, n, "Politica de escrita para usuario anonimo (anon)",
                    "Escrita deve exigir login (to authenticated) e checar o dono.", s[:140])
        if re.search(r"(?i)security\s+definer", s) and not re.search(r"(?i)set\s+search_path", s):
            add("high", "banco-aberto", rel, n, "Funcao SECURITY DEFINER sem 'set search_path'",
                "Adicione  set search_path = ''  e use nomes completos (public.tabela).", s[:140])
        if re.search(r"(?i)\bgrant\s+(all|insert|update|delete)[^;]*\bon\s+(table\s+)?[\w.]+\s+to\s+(anon|public)\b", s):
            add("high", "banco-aberto", rel, n, "GRANT de escrita para anon/public", "Remova; deixe o acesso a cargo do RLS.", s[:140])
        if re.search(r"(?i)alter\s+table[^;]+disable\s+row\s+level\s+security", s):
            add("critical", "banco-aberto", rel, n, "RLS DESATIVADO em tabela", "Nunca desative RLS em tabelas do schema public.", s[:140])
    for t, n in tabelas.items():
        if t not in rls:
            add("critical", "banco-aberto", rel, n, f"Tabela {t} criada SEM Row Level Security",
                f"Rode: alter table {t} enable row level security;  e crie politicas para cada operacao.")


def scan_firebase(rel: str, txt: str):
    if rel.endswith(("firestore.rules", "storage.rules", "database.rules.json")):
        if re.search(r"allow\s+(read|write|read\s*,\s*write)\s*:\s*if\s+true", txt) or re.search(r'"\.(read|write)"\s*:\s*true', txt):
            add("critical", "banco-aberto", rel, 1, "Regras do Firebase abertas (if true)",
                "Exija request.auth != null e compare request.auth.uid com o dono do documento.")


# ---------------------------------------------------------------------------
# 5/6. ROTAS DE API E LIMITE DE TENTATIVAS
# ---------------------------------------------------------------------------
AUTH_MARCAS = re.compile(r"(getUser|getSession|auth\(\)|requireAuth|verifyToken|jwt\.verify|jose|currentUser|getServerSession|"
                         r"clerk|withAuth|authorization|isAuthenticated|session\.user|supabase\.auth|context\.clientContext|"
                         r"x-api-key|verifySignature|webhook.*secret|stripe\.webhooks\.constructEvent)", re.I)
RATE_MARCAS = re.compile(r"(rate.?limit|limiter|throttle|upstash|slowDown|checar_limite|express-rate-limit|@arcjet|captcha|turnstile)", re.I)


def eh_rota(rel: str, txt: str) -> bool:
    r = rel.replace("\\", "/")
    return bool(re.search(r"(^|/)(app/.*/route\.(t|j)sx?|pages/api/|netlify/functions/|netlify/edge-functions/|api/[^/]+\.(t|j)s$|"
                          r"supabase/functions/[^/]+/index\.ts)", r)) or bool(
        re.search(r"\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"'`]/", txt))


def scan_rotas(rel: str, txt: str, estado: dict):
    if not eh_rota(rel, txt):
        return
    estado["rotas"] += 1
    if RATE_MARCAS.search(txt):
        estado["rate"] = True
    muda = re.search(r"(POST|PUT|PATCH|DELETE|\.post\(|\.put\(|\.delete\(|\.patch\(|insert|update|delete\(|upsert)", txt)
    if muda and not AUTH_MARCAS.search(txt):
        add("medium", "api-exposta", rel, 1, "Rota de API que altera dados sem verificacao de login aparente",
            "Verifique o usuario no inicio (ex.: supabase.auth.getUser(token)) e retorne 401 se faltar; confira se ele e dono do recurso (403).")
    if re.search(r"service_role|SERVICE_ROLE|SUPABASE_SERVICE", txt) and not AUTH_MARCAS.search(txt):
        add("high", "api-exposta", rel, 1, "Rota usa a chave service_role sem checar quem esta chamando",
            "Com service_role o RLS e ignorado: valide login e permissao antes de qualquer consulta.")
    for mo in re.finditer(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]", txt):
        n = linha_de(txt, mo.start())
        sev = "high" if re.search(r"Allow-Credentials['\"]?\s*[:,]\s*['\"]?true", txt) else "low"
        add(sev, "api-exposta", rel, n, "CORS liberado para qualquer site (*)",
            "Liste so os dominios do seu site. Nunca use * com credenciais.", linha_txt(txt, n))
    if re.search(r"\bcors\(\s*\)", txt):
        add("low", "api-exposta", rel, 1, "cors() sem opcoes libera todas as origens", "Passe { origin: ['https://seusite.com'] }.")
    if re.search(r"(?i)(stack|err(or)?\.message|e\.message)", txt) and re.search(r"(res\.(json|send)|Response\.json|new Response)\([^)]*(stack|\.message)", txt):
        add("low", "api-exposta", rel, 1, "Erro interno devolvido ao cliente", "Logue o erro no servidor e devolva mensagem generica.")


def scan_login(rel: str, txt: str, estado: dict):
    if re.search(r"signInWithPassword|signInWithEmailAndPassword|/login|login\s*\(", txt) and os.path.splitext(rel)[1] in EXT_CODIGO:
        estado["login"].append(rel)
    if RATE_MARCAS.search(txt) or re.search(r"captchaToken|hcaptcha|turnstile|recaptcha", txt, re.I):
        estado["captcha_ou_rate"] = True


# ---------------------------------------------------------------------------
# 7. PROMPT INJECTION
# ---------------------------------------------------------------------------
LLM = re.compile(r"(openai|@anthropic-ai|anthropic|@ai-sdk|from ['\"]ai['\"]|langchain|llamaindex|@google/generative-ai|google\.generativeai|ollama|groq-sdk|mistralai)")


def scan_prompt(rel: str, txt: str):
    if not LLM.search(txt):
        return
    linhas = txt.splitlines()
    for i, l in enumerate(linhas, 1):
        if re.search(r"(role\s*:\s*['\"]system['\"]|system\s*[:=]\s*[`'\"]|systemPrompt|system_prompt)", l) and re.search(r"\$\{|\+\s*\w|\.format\(|f[\"']", l):
            add("medium", "prompt-injection", rel, i, "Texto variavel dentro do prompt de SISTEMA",
                "Deixe o prompt de sistema fixo; mande dados do usuario como mensagem 'user' separada, delimitada, e trate-os como dados.", l)
        if re.search(r"(innerHTML|dangerouslySetInnerHTML|v-html)", l) and re.search(r"(completion|response|output|message|content|answer|resposta)", l, re.I):
            add("high", "prompt-injection", rel, i, "Resposta do modelo inserida como HTML",
                "Renderize como texto ou markdown sanitizado (DOMPurify). O modelo pode devolver <script> injetado.", l)
        if re.search(r"(child_process|exec\(|execSync|spawn\(|eval\(|fs\.(writeFile|rm|unlink)|subprocess|os\.system|DROP\s+TABLE)", l):
            add("high", "prompt-injection", rel, i, "Arquivo de IA com acao perigosa (shell/arquivos/eval)",
                "Ferramentas do agente devem ser estreitas, com lista permitida, confirmacao humana para acoes destrutivas e sem shell.", l)
    if not re.search(r"(max_tokens|maxTokens|max_output_tokens|maxOutputTokens)", txt):
        add("low", "prompt-injection", rel, 1, "Chamada de IA sem limite de tokens aparente",
            "Defina max_tokens e limite de requisicoes por usuario (custo e abuso).")


# ---------------------------------------------------------------------------
# 8. PACOTES INVENTADOS / TYPOSQUATTING
# ---------------------------------------------------------------------------
POPULARES = ["react", "react-dom", "next", "vue", "nuxt", "svelte", "express", "axios", "lodash", "moment", "dayjs", "zod",
             "prisma", "@prisma/client", "tailwindcss", "vite", "typescript", "eslint", "prettier", "jsonwebtoken", "bcrypt",
             "bcryptjs", "dotenv", "cors", "helmet", "mongoose", "pg", "mysql2", "sequelize", "stripe", "openai",
             "@supabase/supabase-js", "firebase", "socket.io", "nodemailer", "uuid", "chalk", "commander", "jquery",
             "dompurify", "sharp", "multer", "passport", "redis", "ioredis", "graphql", "webpack", "babel", "jest", "vitest",
             "requests", "flask", "django", "fastapi", "numpy", "pandas", "sqlalchemy", "pydantic", "beautifulsoup4",
             "urllib3", "boto3", "pillow", "openpyxl", "httpx", "uvicorn", "jinja2", "cryptography", "pyjwt"]


def distancia(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 1:
        return 2
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def get_json(url: str, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "security-scan/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def checar_pacote(eco: str, nome: str, rel: str, online: bool):
    base = nome.lower()
    for p in POPULARES:
        if base != p and distancia(base.replace("_", "-"), p) == 1 and len(base) > 3:
            add("high", "pacote-inventado", rel, 1, f"'{nome}' e quase igual ao popular '{p}' (possivel typosquatting)",
                f"Confira a grafia. Se queria '{p}', troque e rode a instalacao de novo.")
    if not online:
        return
    try:
        if eco == "npm":
            info = get_json("https://registry.npmjs.org/" + urllib.request.quote(nome, safe="@"))
            criado = (info.get("time") or {}).get("created")
            try:
                dl = get_json("https://api.npmjs.org/downloads/point/last-week/" + urllib.request.quote(nome, safe="@")).get("downloads", 0)
            except Exception:
                dl = None
        else:
            info = get_json(f"https://pypi.org/pypi/{nome}/json")
            rels = [f.get("upload_time_iso_8601") for v in (info.get("releases") or {}).values() for f in v if f.get("upload_time_iso_8601")]
            criado = min(rels) if rels else None
            dl = None
        if criado:
            idade = (datetime.now(timezone.utc) - datetime.fromisoformat(criado.replace("Z", "+00:00"))).days
            if idade < 30:
                add("high", "pacote-inventado", rel, 1, f"'{nome}' foi publicado ha {idade} dias",
                    "Pacotes muito novos sao comuns em ataques. Confirme autor, repositorio e se e mesmo o que a IA sugeriu.")
        if dl is not None and dl < 100:
            add("medium", "pacote-inventado", rel, 1, f"'{nome}' tem so {dl} downloads por semana",
                "Pouco usado: confira o repositorio no GitHub e o autor antes de confiar.")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            add("critical", "pacote-inventado", rel, 1, f"Pacote '{nome}' NAO EXISTE no {'npm' if eco == 'npm' else 'PyPI'} (nome alucinado)",
                "Remova. Alguem pode registrar esse nome com codigo malicioso (slopsquatting). Procure a biblioteca real.")
    except Exception:
        add("info", "pacote-inventado", rel, 1, f"Nao consegui verificar '{nome}' (sem internet?)", "Rode de novo com --online.")


def scan_pacotes(raiz: str, rel: str, txt: str, online: bool):
    nome = os.path.basename(rel)
    if nome == "package.json" and "node_modules" not in rel:
        try:
            pj = json.loads(txt)
        except Exception:
            return
        deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
        for d, v in deps.items():
            if isinstance(v, str) and re.match(r"^(https?:|git\+|github:|file:)", v):
                add("medium", "pacote-inventado", rel, 1, f"'{d}' instalado de URL/git ({v})", "Prefira versoes publicadas e fixadas no lockfile.")
            if v in ("*", "latest"):
                add("medium", "pacote-inventado", rel, 1, f"'{d}' sem versao fixa ({v})", "Fixe a versao (ex.: ^1.2.3) e commit o lockfile.")
            checar_pacote("npm", d, rel, online)
        for s in ("preinstall", "install", "postinstall"):
            if s in pj.get("scripts", {}):
                add("info", "pacote-inventado", rel, 1, f"Script '{s}' roda na instalacao", "Revise o que ele executa.")
        pasta = os.path.dirname(os.path.join(raiz, rel))
        if deps and not any(os.path.exists(os.path.join(pasta, f)) for f in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")):
            add("low", "pacote-inventado", rel, 1, "Sem lockfile", "Commit o package-lock.json para travar as versoes exatas.")
    elif nome in ("requirements.txt", "requirements-dev.txt"):
        for i, l in enumerate(txt.splitlines(), 1):
            mo = re.match(r"^\s*([A-Za-z0-9_.\-]+)", l)
            if mo and not l.strip().startswith(("#", "-")):
                checar_pacote("pypi", mo.group(1), rel, online)


def scan_cdn(rel: str, txt: str):
    for mo in re.finditer(r"<script[^>]+src=[\"'](https?://[^\"']+)[\"'][^>]*>", txt, re.I):
        tag, url = mo.group(0), mo.group(1)
        n = linha_de(txt, mo.start())
        if re.search(r"(cdn\.jsdelivr|unpkg|cdnjs|esm\.sh|skypack)", url):
            if re.search(r"@latest|@\d+(/|$)|@\d+\.\d+(/|$)", url) or not re.search(r"@\d+\.\d+\.\d+|/\d+\.\d+\.\d+/", url):
                add("medium", "pacote-inventado", rel, n, "Script de CDN sem versao exata", "Use a versao completa (ex.: @2.45.4).", tag)
            if "integrity=" not in tag:
                add("low", "pacote-inventado", rel, n, "Script de CDN sem integrity (SRI)",
                    "Adicione integrity=\"sha384-...\" crossorigin=\"anonymous\" para o navegador recusar arquivo alterado.", tag)


# ---------------------------------------------------------------------------
# 9. CABECALHOS E ARQUIVOS PUBLICADOS
# ---------------------------------------------------------------------------
def scan_headers(raiz: str, arquivos: list[str]):
    htmls = [a for a in arquivos if a.endswith((".html", ".htm"))]
    cfgs = {}
    for nome in ("netlify.toml", "_headers", "vercel.json", "public/_headers", "static/_headers"):
        p = os.path.join(raiz, nome)
        if os.path.exists(p):
            cfgs[nome] = open(p, encoding="utf-8", errors="ignore").read()
    if not htmls and not cfgs:
        return
    if not cfgs:
        add("medium", "cabecalhos", ".", 1, "Nenhum arquivo de cabecalhos de seguranca (netlify.toml/_headers/vercel.json)",
            "Crie um com Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, frame-ancestors e HSTS. Veja references/netlify.md.")
        return
    tudo = "\n".join(cfgs.values())
    nome = next(iter(cfgs))
    regras = [("Content-Security-Policy", "medium", "Sem Content-Security-Policy (principal defesa extra contra XSS)"),
              ("X-Content-Type-Options", "low", "Sem X-Content-Type-Options: nosniff"),
              ("Referrer-Policy", "low", "Sem Referrer-Policy"),
              ("Strict-Transport-Security", "low", "Sem HSTS (Strict-Transport-Security)")]
    for h, sev, msg in regras:
        if h.lower() not in tudo.lower():
            add(sev, "cabecalhos", nome, 1, msg, f"Adicione o cabecalho {h}. Veja references/netlify.md.")
    if "frame-ancestors" not in tudo and "X-Frame-Options" not in tudo:
        add("low", "cabecalhos", nome, 1, "Site pode ser colocado em iframe (clickjacking)", "Use frame-ancestors 'none' na CSP ou X-Frame-Options: DENY.")
    csp = re.search(r"Content-Security-Policy[\"']?\s*[=:]\s*[\"']([^\"']+)", tudo)
    if csp and re.search(r"script-src[^;]*'unsafe-eval'", csp.group(1)):
        add("medium", "cabecalhos", nome, 1, "CSP permite 'unsafe-eval'", "Remova 'unsafe-eval' (so libs muito antigas precisam).")
    if csp and re.search(r"script-src[^;]*'unsafe-inline'", csp.group(1)):
        add("info", "cabecalhos", nome, 1, "CSP permite scripts inline ('unsafe-inline')",
            "Funciona, mas protege menos. Para endurecer, mova o JS para arquivos .js e troque onclick por addEventListener.")


def scan_publicados(raiz: str, arquivos: list[str]):
    redir = ""
    for nome in ("netlify.toml", "_redirects"):
        p = os.path.join(raiz, nome)
        if os.path.exists(p):
            redir += open(p, encoding="utf-8", errors="ignore").read()
    for a in arquivos:
        base = os.path.basename(a)
        if base.startswith(".env") and base not in (".env.example", ".env.sample", ".env.template"):
            ign = os.path.join(raiz, ".gitignore")
            ok = os.path.exists(ign) and re.search(r"^\.env", open(ign, encoding="utf-8", errors="ignore").read(), re.M)
            add("high" if not ok else "low", "chave-exposta", a, 1, "Arquivo .env no projeto" + ("" if ok else " e fora do .gitignore"),
                "Coloque .env no .gitignore. Se ja foi para o GitHub, troque todas as chaves dele.")
        if re.search(r"\.(sql|bak|dump|sqlite3?|db|pem|key)$", base) and "/" not in a.strip("./"):
            if base not in redir:
                add("low", "chave-exposta", a, 1, f"'{base}' fica publico se a pasta inteira for publicada",
                    "Tire da pasta publicada ou bloqueie com redirect 404 no netlify.toml.")


# ---------------------------------------------------------------------------
def listar(raiz: str):
    out = []
    for dp, dns, fns in os.walk(raiz):
        dns[:] = [d for d in dns if d not in PULAR_PASTAS and not d.startswith(".git")]
        for f in fns:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, raiz)
            ext = os.path.splitext(f)[1].lower()
            if ext in EXT_TEXTO or f.startswith(".env") or f in ("_headers", "_redirects", "firestore.rules", "storage.rules"):
                try:
                    if os.path.getsize(p) <= MAX_BYTES and not f.endswith((".min.js", ".min.css")):
                        out.append(rel)
                except OSError:
                    pass
    return sorted(out)


def main():
    ap = argparse.ArgumentParser(description="Scanner de seguranca para sites/apps web")
    ap.add_argument("pasta", nargs="?", default=".")
    ap.add_argument("--online", action="store_true", help="consulta npm/PyPI para achar pacotes inventados")
    ap.add_argument("--json", action="store_true", help="saida em JSON")
    ap.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "none"])
    ap.add_argument("--min", default="low", choices=SEVERIDADES, help="esconde achados abaixo desta severidade")
    a = ap.parse_args()
    raiz = os.path.abspath(a.pasta)
    arquivos = listar(raiz)
    estado = {"rotas": 0, "rate": False, "login": [], "captcha_ou_rate": False}
    for rel in arquivos:
        try:
            txt = open(os.path.join(raiz, rel), encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        ext = os.path.splitext(rel)[1].lower()
        scan_segredos(rel, txt)
        if ext in EXT_CODIGO:
            scan_xss(rel, txt)
            scan_sqli(rel, txt)
            scan_rotas(rel, txt, estado)
            scan_login(rel, txt, estado)
            scan_prompt(rel, txt)
        if ext == ".sql":
            scan_sqli(rel, txt)
            scan_sql_banco(rel, txt)
            if re.search(r"checar_limite|rate_limit|limites", txt):
                estado["captcha_ou_rate"] = estado["rate"] = True
        if ext in (".html", ".htm"):
            scan_cdn(rel, txt)
        scan_firebase(rel, txt)
        scan_pacotes(raiz, rel, txt, a.online)
    scan_headers(raiz, arquivos)
    scan_publicados(raiz, arquivos)
    if estado["rotas"] and not estado["rate"]:
        add("medium", "limite-tentativas", ".", 1, f"{estado['rotas']} rota(s) de API e nenhum limite de requisicoes encontrado",
            "Adicione rate limit (ex.: Upstash Ratelimit, tabela de limites no Postgres, Netlify Edge). Veja references/limite-tentativas.md.")
    if estado["login"] and not estado["captcha_ou_rate"]:
        add("low", "limite-tentativas", estado["login"][0], 1, "Login sem CAPTCHA nem limite de tentativas no codigo",
            "Ative CAPTCHA (Turnstile/hCaptcha) e confira os Rate Limits em Supabase > Authentication.")

    ordem = {s: i for i, s in enumerate(SEVERIDADES)}
    vis = sorted([x for x in ACHADOS if ordem[x.severidade] <= ordem[a.min]], key=lambda x: (ordem[x.severidade], x.categoria, x.arquivo, x.linha))
    if a.json:
        print(json.dumps([asdict(x) for x in vis], ensure_ascii=False, indent=2))
    else:
        print(f"\nScanner de seguranca - {raiz}\n{len(arquivos)} arquivos analisados\n")
        if not vis:
            print("Nenhum problema encontrado nas verificacoes automaticas. Ainda faca a revisao manual (references/checklist.md).")
        for x in vis:
            print(f"[{ROTULO[x.severidade]}] ({x.categoria}) {x.arquivo}:{x.linha}\n   {x.mensagem}\n   -> {x.correcao}")
            if x.trecho:
                print(f"   | {x.trecho}")
            print()
        cont = {s: sum(1 for x in ACHADOS if x.severidade == s) for s in SEVERIDADES}
        print("Resumo: " + ", ".join(f"{ROTULO[s]}: {cont[s]}" for s in SEVERIDADES))
        print("Lembrete: o scanner e heuristico. Ele aponta o que revisar; nao garante que esta tudo seguro.")
    if a.fail_on != "none" and any(ordem[x.severidade] <= ordem[a.fail_on] for x in ACHADOS):
        sys.exit(1)


if __name__ == "__main__":
    main()
