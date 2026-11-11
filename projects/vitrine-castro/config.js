// =====================================================================
//  CONFIGURAÇÃO DO VITRINE CASTRO  –  é o ÚNICO arquivo que você preenche
//  Coloque os valores entre as aspas "" e publique de novo no Netlify.
//  Guia completo: COMO-PUBLICAR.txt
// =====================================================================
window.CONFIG = {

  // 1) SUPABASE (banco de dados) – em supabase.com > seu projeto > Project Settings > API Keys
  SUPABASE_URL: "",        // o "Project URL", ex: "https://abcdefgh.supabase.co"
  SUPABASE_ANON_KEY: "",   // a chave PÚBLICA: "publishable" (começa com sb_publishable_) ou "anon public"
                           // NUNCA coloque aqui a "secret", a "service_role" ou a senha do banco.

  // 2) WHATSAPP DO VITRINE (administrador) – recebe clientes do VIP, lojistas e suporte
  WHATSAPP: "",            // só números, com 55 + DDD, ex: "5542999999999"

  // 3) PIX PARA RECEBER O VITRINE VIP (e citado nas cobranças de mensalidade)
  PIX: "",                 // sua chave Pix: e-mail, CPF/CNPJ (só números), celular "+5542999999999" ou chave aleatória
  PIX_NOME: "",            // nome de quem recebe, igual aparece no banco (ex: "VITRINE CASTRO"), até 25 letras
  PIX_CIDADE: "CASTRO",    // cidade de quem recebe

  // 4) RESPONSÁVEL PELO APP (aparece em "Privacidade e termos", exigido pela LGPD)
  RESPONSAVEL: "",         // nome completo de quem responde pelo Vitrine
  DOCUMENTO: "",           // CPF ou CNPJ, ex: "CPF 000.000.000-00"
  EMAIL: ""                // e-mail para dúvidas sobre dados
};
