# Vitrine Castro – Clube de Desconto

App web (PWA) de ofertas, cupons, pontos e brindes do comércio de Castro-PR.

## Publicar na Netlify
1. Preencha `config.js` (Supabase, WhatsApp e, se quiser, Instagram).
2. No Supabase, rode `supabase.sql` no SQL Editor (uma vez).
3. Arraste a pasta inteira no painel da Netlify (o `netlify.toml` já configura cache e segurança).

## O que foi melhorado (com base no repositório ui-ux-pro-max)
- **Design system** gerado pelo motor do repositório (`design-system/vitrine-castro/MASTER.md`), ajustado à marca.
- **Tokens de cor semânticos** e **modo escuro** (automático, claro ou escuro em Perfil → Aparência).
- **Ícones SVG** no lugar de emojis na interface (navegação, menus, botões, categorias, brindes).
- **Acessibilidade:** foco preso no modal, Esc fecha, foco volta ao botão de origem, "pular para o conteúdo",
  `aria-pressed`/`aria-current`, avisos lidos por leitor de tela, contraste de texto ≥ 4.5:1,
  carrossel com botão de pausa e que para ao tocar/focar, respeito a "reduzir movimento".
- **Botão Voltar do celular** funciona entre as telas e fecha janelas abertas.
- **Novidades para o cliente:** seção "Terminando logo", ordenar ofertas (destaques, prazo, economia, A–Z),
  página da loja (todas as ofertas, WhatsApp, "Como chegar"), marcar cupom como usado (economia real),
  avisos com "lido/não lido", "Como funciona" em 3 passos para quem é novo, tabela Grátis × VIP,
  perguntas frequentes, editar dados, privacidade (LGPD) com "apagar meus dados", rodapé, compartilhamento nativo do celular.
- **Carregamento:** esqueleto (skeleton) enquanto busca as ofertas no banco, aviso de "sem internet".
- **Tablet/computador:** layout se adapta (3–4 colunas de ofertas, janelas centralizadas).
- **Área da Empresa:** modo escuro, resumo (no ar / pausadas / vencidas), alerta de oferta vencendo,
  contador de caracteres e **prévia ao vivo** de como a oferta aparece no app.
- **SEO/compartilhamento:** Open Graph para WhatsApp/Facebook, dados estruturados, atalhos do app instalado.
