// ===== CONFIGURAÇÃO DO VITRINE CASTRO =====
// Tudo aqui é PÚBLICO (qualquer pessoa vê no navegador). Por isso:
//  - use SOMENTE a chave "anon public" do Supabase;
//  - NUNCA coloque aqui a chave "service_role", senhas, tokens de pagamento
//    ou chaves de API de outros serviços. A proteção dos dados vem das regras
//    do supabase.sql (Row Level Security), não de esconder esta chave.
// Deixe SUPABASE_URL vazio para ver o app em MODO DEMONSTRAÇÃO.
window.CONFIG = {
  SUPABASE_URL: "",        // ex: "https://abcdefgh.supabase.co"
  SUPABASE_ANON_KEY: "",   // a chave "anon public" (NUNCA a service_role)
  WHATSAPP: "",            // seu número com 55 + DDD, ex: "5542999999999"
  PIX: "",                 // opcional: sua chave Pix para receber o VIP (R$ 9,90) e os planos
  INSTAGRAM: ""            // opcional: seu @ do Instagram, ex: "vitrinecastro" (aparece no rodapé)
};
