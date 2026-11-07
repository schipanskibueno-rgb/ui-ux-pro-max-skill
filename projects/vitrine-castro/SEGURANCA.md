# Publicar o Vitrine Castro com segurança

Tempo: ~30 minutos. Você precisa de uma conta grátis no **Supabase** e na **Netlify**.

## 1. Supabase – banco de dados
1. Crie um projeto em https://supabase.com (região **São Paulo**). Guarde a senha do banco num gerenciador de senhas.
2. **SQL Editor > New query**: cole todo o `supabase.sql` e clique **Run**. (Pode rodar de novo quando houver versão nova: não apaga dados.)
3. **Database > Advisors > Security Advisor**: não deve haver alerta vermelho.

## 2. Supabase – login (Authentication)
1. **Sign In / Providers > Email**: deixe **Confirm email** ligado. Senha mínima: **8**.
2. **URL Configuration**:
   - *Site URL*: o endereço do seu site (ex.: `https://vitrinecastro.netlify.app`).
   - *Redirect URLs*: só os seus endereços (`https://vitrinecastro.netlify.app/**`, e o domínio próprio se tiver). Nada de `*`.
3. **Attack Protection**: ative **CAPTCHA** (Cloudflare Turnstile é grátis) quando o site estiver no ar. *Obs.: com CAPTCHA ligado, o app precisa enviar o token; peça para adicionarmos o widget quando for ativar.*
4. **Rate Limits**: mantenha os padrões ou reduza o de e-mails por hora.
5. Em produção, configure **SMTP próprio** (ex.: Resend ou Brevo) em *Emails > SMTP Settings*: o e-mail padrão do Supabase tem limite baixo.

## 3. Chaves – o que vai no site
Em **Project Settings > API Keys** copie:
- **Project URL** → `SUPABASE_URL` no `config.js`
- **anon / publishable key** → `SUPABASE_ANON_KEY` no `config.js`

⚠️ **NUNCA** coloque a **service_role / secret key** no `config.js`, no código ou no WhatsApp. Ela ignora todas as regras de segurança. Este app não precisa dela.

A chave anon **é pública de propósito**: quem protege os dados são as regras do `supabase.sql` (Row Level Security).

## 4. Netlify – publicar
1. Preencha `config.js` (Supabase, WhatsApp, Pix).
2. Em https://app.netlify.com: **Add new site > Deploy manually** e arraste a pasta inteira.
3. **Domain management**: ative **HTTPS** (automático) e “Force HTTPS”.
4. Ative **2FA** na conta da Netlify, do Supabase e do GitHub.
5. Teste os cabeçalhos em https://securityheaders.com (deve dar nota A).

O `netlify.toml` já envia: CSP (só carrega scripts do próprio site e das CDNs usadas, com SRI), HSTS, nosniff, proteção contra iframe e bloqueia o download do `supabase.sql` e dos `.md`.

## 5. Virar administrador
1. Abra `seusite/empresa.html`, crie sua conta e confirme o e-mail.
2. No SQL Editor rode (com o SEU e-mail):
   ```sql
   insert into public.admins (user_id) select id from auth.users where email = 'SEU_EMAIL_AQUI';
   ```
3. Entre de novo na Área da Empresa: aparece a aba **👑 Admin**.

## 6. Operar o dia a dia (aba Admin)
- **Aprovar lojas**: só lojas aprovadas aparecem no app e podem confirmar compras.
- **Planos das empresas** (R$ 49,90 / 99,90 / 199,90): recebeu o pagamento → escolha o plano e toque **+30 dias**. Venceu e não pagou → volta sozinho para o Grátis (1 oferta/semana).
- **VIP dos clientes** (R$ 9,90): o cliente manda o comprovante pelo WhatsApp com o e-mail → busque o e-mail → **👑 +30 dias**.
- **Brindes**: cadastre (nome, pontos, estoque, quem entrega). Ex.: “Vale-bônus R$ 10” = 1.000 pontos, entregue por uma loja parceira que topou.
- **Destaque e vitrine**: você pode ligar/desligar em qualquer oferta.

> **Pagamento automático:** hoje o VIP e os planos são liberados manualmente depois do Pix (seguro e sem custo). Para cobrança automática (Mercado Pago/Asaas/Stripe), o certo é uma **Supabase Edge Function** que recebe o webhook do provedor, **valida a assinatura**, confere o pagamento na API do provedor e só então chama `admin_dar_vip`/`admin_plano` com a chave service_role guardada em `supabase secrets`. Nunca libere VIP a partir de um aviso vindo do navegador.

## 7. Como a loja confirma a compra
1. Cliente abre o cupom no app (QR Code).
2. Caixa abre `empresa.html` > **📷 Confirmar compra** > **Tirar foto do QR Code** (ou digita o código).
3. Confere cliente, produto e desconto, digita o **valor pago** e confirma.
4. O cliente vê **“Compra confirmada! +X pontos”** na hora; a venda fica na aba **🧾 Vendas** (com planilha CSV).

## 8. Antes de cada atualização
```bash
python3 .claude/skills/web-security-shield/scripts/security_scan.py projects/vitrine-castro
```
Não publique com achado CRÍTICO ou ALTO. Depois, faça o teste de 2 minutos: logado como cliente, abra o console do navegador e tente
```js
await supabase.from('perfis').update({ vip_ate: '2099-01-01' }).eq('id', (await supabase.auth.getUser()).data.user.id)
```
O VIP **não** pode mudar.
