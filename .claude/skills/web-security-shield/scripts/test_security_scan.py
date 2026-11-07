#!/usr/bin/env python3
"""Testes do security_scan.py.

Os arquivos vulneraveis sao criados numa pasta temporaria NA HORA do teste
(as chaves falsas sao montadas por partes) para que nenhum segredo de mentira
fique salvo no repositorio e dispare alertas do GitHub.
Rode:  python3 test_security_scan.py
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(AQUI, "security_scan.py")


def jwt(role):
    def b(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return b({"alg": "HS256", "typ": "JWT"}) + "." + b({"iss": "supabase", "role": role, "ref": "abcdefghijkl"}) + "." + "x" * 43


def escrever(raiz, rel, txt):
    p = os.path.join(raiz, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(txt)


def rodar(pasta, *extra):
    r = subprocess.run([sys.executable, "-I", SCANNER, pasta, "--json", "--min", "info", *extra], capture_output=True, text=True)
    return r.returncode, json.loads(r.stdout or "[]")


def main():
    falhas = 0
    with tempfile.TemporaryDirectory() as ruim:
        stripe = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "AbCdEf"
        escrever(ruim, "src/config.js", f'export const supa = "{jwt("service_role")}";\nconst STRIPE = "{stripe}";\n'
                                        'const cfg = { apiKey: "abc123def456ghi789" };\n')
        escrever(ruim, "src/app.js", 'function mostrar(c){ lista.innerHTML = `<li>${c.nome}</li>`; }\n'
                                     'function busca(){ out.innerHTML = `<p>${location.hash.slice(1)}</p>`; }\n'
                                     'setTimeout("alert(1)", 10);\n')
        escrever(ruim, "src/db.js", 'db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n'
                                    'db.query("SELECT * FROM users WHERE email = \'" + email + "\'");\n')
        escrever(ruim, "supabase/schema.sql", "create table public.pedidos (id uuid primary key, total numeric);\n"
                                              "create table public.perfis (id uuid primary key);\n"
                                              "alter table public.perfis enable row level security;\n"
                                              "create policy \"tudo\" on public.perfis for update using (true);\n"
                                              "create function public.f() returns void language sql security definer as $$ select 1 $$;\n")
        escrever(ruim, "app/api/pedidos/route.ts", "export async function POST(req){ const b = await req.json();\n"
                                                   " await supabase.from('pedidos').insert(b); return Response.json({ok:true}); }\n")
        escrever(ruim, "app/api/chat/route.ts", "import OpenAI from 'openai';\nconst r = await client.chat.completions.create({messages:[{role:'system', content:`Voce ajuda ${usuario.pedido}`}]});\n"
                                                "div.innerHTML = r.choices[0].message.content;\n")
        escrever(ruim, "package.json", json.dumps({"dependencies": {"expresss": "^4.0.0", "lodash": "latest"}}))
        escrever(ruim, "index.html", '<script src="https://cdn.jsdelivr.net/npm/somelib@latest"></script>\n<a href="https://x.com" target="_blank">x</a>\n')
        escrever(ruim, ".env", "OPENAI_API_KEY=troque\n")
        escrever(ruim, "firestore.rules", "service cloud.firestore { match /{d=**} { allow read, write: if true; } }")

        code, achados = rodar(ruim)
        cats = {(a["categoria"], a["severidade"]) for a in achados}
        msgs = " | ".join(a["mensagem"] for a in achados)
        esperado = [
            ("chave-exposta", "critical", "service_role"),
            ("chave-exposta", "critical", "Stripe"),
            ("xss", "medium", "location.hash"),
            ("xss", "low", "para revisar"),
            ("xss", "high", "eval"),
            ("sql-injection", "high", "template string"),
            ("sql-injection", "high", "concatenado"),
            ("banco-aberto", "critical", "pedidos"),
            ("banco-aberto", "high", "(true)"),
            ("banco-aberto", "high", "search_path"),
            ("banco-aberto", "critical", "Firebase"),
            ("api-exposta", "medium", "sem verificacao de login"),
            ("limite-tentativas", "medium", "rota(s) de API"),
            ("prompt-injection", "medium", "SISTEMA"),
            ("prompt-injection", "high", "como HTML"),
            ("pacote-inventado", "high", "express"),
            ("pacote-inventado", "medium", "sem versao"),
            ("cabecalhos", "medium", "Nenhum arquivo de cabecalhos"),
            ("chave-exposta", "high", ".env"),
        ]
        for cat, sev, trecho in esperado:
            ok = any(a["categoria"] == cat and a["severidade"] == sev and trecho in a["mensagem"] for a in achados)
            print(("OK   " if ok else "FALHA"), cat, sev, trecho)
            falhas += not ok
        if code != 1:
            print("FALHA: codigo de saida deveria ser 1 com achados criticos"); falhas += 1
        segredo_no_relatorio = any(stripe in (a.get("trecho") or "") for a in achados)
        print(("OK   " if not segredo_no_relatorio else "FALHA"), "relatorio mascara o segredo")
        falhas += segredo_no_relatorio

    with tempfile.TemporaryDirectory() as bom:
        escrever(bom, "index.html", "<script>function esc(s){return String(s).replace(/[&<>\"']/g,'')}\n"
                                    "el.innerHTML = `<b>${esc(item.nome)}</b> ${Number(item.preco)}`;</script>\n")
        escrever(bom, "schema.sql", "create table public.t (id int);\nalter table public.t enable row level security;\n"
                                    "create policy p on public.t for select using (true);\n"
                                    "create function public.g() returns int language sql security definer set search_path = '' as $$ select 1 $$;\n")
        escrever(bom, "netlify.toml", '[[headers]]\n  for="/*"\n  [headers.values]\n    Content-Security-Policy = "default-src \'self\'; frame-ancestors \'none\'"\n'
                                      '    X-Content-Type-Options = "nosniff"\n    Referrer-Policy = "no-referrer"\n    Strict-Transport-Security = "max-age=31536000"\n')
        code, achados = rodar(bom)
        graves = [a for a in achados if a["severidade"] in ("critical", "high", "medium")]
        print(("OK   " if not graves and code == 0 else "FALHA"), "projeto correto sem falso positivo grave", graves)
        falhas += bool(graves) or code != 0

    print("\n" + ("TODOS OS TESTES PASSARAM" if not falhas else f"{falhas} FALHA(S)"))
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main()
