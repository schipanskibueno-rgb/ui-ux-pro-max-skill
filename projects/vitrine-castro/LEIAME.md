# Vitrine Castro – ofertas locais de Castro-PR

App web (PWA) de ofertas **só das lojas de Castro**: as empresas publicam produtos com **10, 20, 30 ou 50% de desconto**, os clientes pegam o cupom, mostram o **QR Code** no caixa, a loja tira uma foto do QR e informa o valor, e o cliente ganha **pontos** que viram **brindes e vale-bônus**.

| Quem | O que tem |
|---|---|
| **Cliente (grátis)** | Descontos normais, cupons com QR Code, pontos (1 por real), níveis Bronze/Prata/Ouro, brindes, indicação de amigos (+100 pontos quando o amigo faz a 1ª compra) |
| **Cliente VIP – R$ 9,90/mês** | Desconto VIP maior (quando a loja oferece), vê as ofertas novas **24h antes**, pontos **em dobro** |
| **Empresa – Grátis** | 1 oferta por semana, confirmação de compras pelo QR Code, relatório de vendas |
| **Empresa – Vitrine R$ 49,90** | 3 ofertas/semana + aparece na **vitrine principal** (carrossel) |
| **Empresa – Destaque R$ 99,90** | 7 ofertas/semana + vitrine + “Ofertas em destaque” |
| **Empresa – Premium R$ 199,90** | 15 ofertas/semana + primeiro lugar na vitrine + aviso aos clientes |

## Arquivos
| Arquivo | Para quê |
|---|---|
| `index.html` | App do cliente. Sem `config.js` preenchido roda em **modo demonstração** (dados no celular). |
| `empresa.html` | Área da Empresa: ofertas, **Confirmar compra** (foto do QR), vendas, plano e painel do administrador. |
| `supabase.sql` | Banco completo com todas as regras de segurança. Rode no SQL Editor do Supabase. |
| `config.js` | URL e chave **anon** do Supabase, WhatsApp, Pix, Instagram. |
| `netlify.toml` | Cabeçalhos de segurança (CSP, HSTS…), cache e bloqueio de arquivos internos. |
| `sw.js`, `manifest.webmanifest` | Funciona offline e pode ser instalado no celular. |
| `SEGURANCA.md` | **Passo a passo para publicar com segurança** (Supabase + Netlify) e operar VIP/planos. |

## Publicar
Siga o **SEGURANCA.md**. Resumo: criar projeto no Supabase → rodar `supabase.sql` → ajustar Authentication → preencher `config.js` → arrastar a pasta na Netlify → virar administrador.

## Como o sistema se protege (resumo)
- Pontos, VIP, plano, aprovação e limite semanal **só mudam no banco**, por funções que conferem quem chama. O cliente não consegue se dar pontos nem virar VIP pelo navegador.
- A loja só confirma cupons **das próprias ofertas**, uma vez só, e não pode confirmar o próprio cupom.
- Bônus de boas-vindas e de indicação só saem na **1ª compra confirmada** (evita contas falsas).
- Limites de tentativas: 20 cupons/dia por cliente, 60 consultas de código a cada 10 min por loja, 10 trocas/dia.
- Tudo que vem do usuário é exibido como texto (proteção contra XSS); scripts de CDN com versão fixa e SRI; CSP na Netlify.
- Verificado com o scanner da skill `web-security-shield` (`.claude/skills/web-security-shield/scripts/security_scan.py`).
