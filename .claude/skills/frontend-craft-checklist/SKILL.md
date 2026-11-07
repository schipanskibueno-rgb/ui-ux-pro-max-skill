---
name: frontend-craft-checklist
description: "Checklist de acabamento profissional para sites e apps web: modos de interface (persuadir, operar, ler, experiência), regras anti-'cara de template feito por IA', estados completos de botões/links/campos, robustez (texto longo, sem internet, clique duplo, vazio, erro), movimento com propósito (tempos, easing, prefers-reduced-motion, uso correto do animate.css) e entrega (404, favicon, fontes, mobile-first). Destilado do Front-End Design Checklist, taste-skill, impeccable e animate.css. Use ao finalizar, polir, revisar ou endurecer qualquer interface web, ao adicionar animações, ou quando o site 'parece genérico', 'parece feito por IA' ou 'não parece profissional'."
---

# Frontend Craft Checklist

Complementa a `ui-ux-pro-max` (que escolhe estilo, cor, fonte) e a `web-security-shield` (que protege). Esta skill garante o **acabamento**: o que separa um site "que funciona" de um site que parece feito por uma empresa séria.

## 1. Descubra o modo da tela antes de desenhar

| Modo | O visitante quer… | Prioridade | Exemplos |
|---|---|---|---|
| **Persuadir** | decidir e agir | impacto, prova, um CTA claro por tela | landing page, página de planos, campanha |
| **Operar** | concluir uma tarefa | rapidez, consistência, padrões nativos, pouca firula | app, painel, área do lojista, checkout |
| **Ler** | entender | hierarquia de texto, largura de leitura (60–75 caracteres) | ajuda, FAQ, termos, blog |
| **Experiência** | apreciar a obra | a obra em primeiro plano, interface discreta | portfólio, galeria |

O modo é da **tela**, não do produto: o app de ofertas é *Operar*, mas a página "Seja parceiro" é *Persuadir*. Em *Operar*, ambição aparece como precisão, não como efeito.

## 2. Regras anti "cara de template"

1. **O tipo de negócio decide o visual.** Comércio local (loja, café, salão, clínica) = **fotos reais** do produto e do lugar, cores chapadas, tipografia forte. Efeitos de shader, partículas, fundos "tech" e telas escuras dramáticas são para software/IA/games, nunca para a padaria.
2. **Diga claramente o que se vende** no primeiro olhar. Texto simples, com voz própria, sem jargão ("soluções inovadoras" ❌; "20% de desconto na pizza grande" ✅).
3. **Uma ação principal por tela.** Ações secundárias com visual secundário.
4. **Margens esquerda e direita iguais**; um único sistema de espaçamento (4/8 px).
5. **Sem legenda descritiva embaixo de foto** (a foto fala; crédito vai no rodapé).
6. **Um estilo de botão primário**, um secundário. Nada de 5 cores de botão.
7. **Ícones de uma família só** (SVG, mesmo traço). Emoji não é ícone de interface.
8. **Conteúdo real** desde o início (idioma certo, nomes e preços plausíveis), nunca lorem ipsum.
9. **Endereços e contatos de exemplo** não podem parecer reais de terceiros (use domínios `.example`, sem número de telefone real).

## 3. Estados de todo elemento interativo

Antes de entregar, cada componente precisa ter estes estados definidos e visíveis, **no tema claro e no escuro**:

| Elemento | Estados obrigatórios |
|---|---|
| Link | normal, hover, **focus visível**, ativo, visitado (quando fizer sentido) |
| Botão | normal, hover, focus, pressionado, **desabilitado** (com `disabled`), **carregando** ("Salvando…") |
| Campo | vazio com label visível (placeholder não é label), foco, preenchido, **erro perto do campo**, desabilitado; indicação de obrigatório/opcional |
| Lista/tela | carregando (skeleton), **vazia com ação**, erro com "tentar de novo", sem internet |
| Janela/modal | abrir/fechar, Esc fecha, foco preso dentro, foco volta ao botão de origem, Voltar do celular fecha |

## 4. Robustez (teste antes de dizer "pronto")

- **Texto longo**: nome de 100+ caracteres, título sem espaço, emoji nos campos → nada estoura o layout.
- **Rede**: desligue a internet e deixe lenta (DevTools > Network > Slow 3G) → mensagens claras, nada trava.
- **Clique duplo / 10 cliques rápidos** em "Enviar" → uma ação só (desabilite o botão enquanto envia; o servidor também precisa ser idempotente).
- **Vazio**: banco sem dados → telas vazias explicam e oferecem a próxima ação.
- **Erros forçados**: API devolvendo 400/500 → mensagem humana, sem stack trace.
- **Volume**: 1.000 itens → lista continua usável (paginação/limite).
- **Gestos interrompidos**: arrastar o carrossel e soltar fora, segundo dedo no meio → estado consistente.
- **Zoom 200% e letra grande do sistema** → nada cortado, sem rolagem horizontal.

## 5. Movimento com propósito

Animação só quando explica algo: **confirma uma ação, mostra mudança de estado, mantém continuidade** entre telas ou cria **um** momento marcante merecido. Decoração sem motivo é "dívida de animação".

| Duração | Uso |
|---|---|
| 100–150 ms | resposta imediata (toque, hover) |
| 150–300 ms | mudança de estado comum |
| 300–500 ms | painel/modal, troca de tela |
| 500–800 ms | **um** momento de destaque autoral (ex.: cupom "carimbado", pontos ganhos) |

- Saída mais rápida que entrada. Easing de chegada confiante: `cubic-bezier(0.16, 1, 0.3, 1)`. Não use bounce/elastic por reflexo.
- Anime `transform` e `opacity`; evite animar `width/height/top/left/margin` (causa travamento e layout shift).
- **`prefers-reduced-motion`**: sempre um caminho reduzido, removendo deslocamento mas mantendo cor/opacidade que comunicam estado.
- Laços (carrossel automático, brilho) param fora da tela, com a aba oculta e têm botão de pausa.
- No máximo 1–2 elementos animando por tela.

### animate.css do jeito certo
O animate.css (biblioteca de keyframes prontos) é ótimo para protótipos e momentos pontuais:
```html
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/animate.css@4.1.1/animate.min.css" integrity="sha384-Gu3KVV2H9d+yA4QDpVB7VcOyhJlAVrcXd0thEjr4KznfaFPLe0xQJyonVxONa4ZC" crossorigin="anonymous">
<div class="animate__animated animate__bounceIn" style="--animate-duration:.5s">Cupom garantido!</div>
```
```js
function animar(el, nome){ el.classList.add('animate__animated', 'animate__' + nome);
  el.addEventListener('animationend', () => el.classList.remove('animate__animated', 'animate__' + nome), { once: true }); }
```
- Escolha pelo **significado**: sucesso → `bounceIn`/`tada` (curto); favoritar → `heartBeat`; erro → `headShake`/`shakeX` discreto; entrada de painel → `fadeInUp`/`slideInUp`.
- Ele já respeita `prefers-reduced-motion` (desliga as animações); mantenha isso.
- Precisa de 2 ou 3 efeitos? Copie só esses `@keyframes` (com crédito) em vez de carregar a biblioteca inteira (~70 KB). Verifique a licença (Hippocratic 2.1) para uso comercial.
- Nunca anime tudo que entra na tela; nunca use `animate__infinite` em conteúdo.

## 6. Entrega

- [ ] Página **404** desenhada (e 500 se houver servidor)
- [ ] Favicon + ícone 512×512 PNG + `apple-touch-icon`; `manifest` para PWA
- [ ] Fontes: no máximo 2 famílias, peso total < 1–2 MB, `font-display: swap`, pilha de fallback
- [ ] Imagens com `width/height` (sem layout shift), `loading="lazy"` abaixo da dobra, formatos modernos (WebP/AVIF) e tamanho adequado
- [ ] Mobile-first: testado em 375, 768, 1024 e 1440 px; sem rolagem horizontal; alvos de toque ≥ 44 px
- [ ] Cores com nomes de uso (tokens: `--surface`, `--text`, `--danger`), tema claro e escuro conferidos separadamente (contraste ≥ 4,5:1)
- [ ] Meta tags de compartilhamento (Open Graph) e título por página
- [ ] Um guia de estilo/design system escrito (ex.: `design-system/MASTER.md` da ui-ux-pro-max)
- [ ] Segurança: rode a skill `web-security-shield` antes de publicar

## 7. Verificação

Olhe o resultado renderizado nos tamanhos reais (screenshot em 390 e 1280 px, tema claro e escuro), **conserte tudo que uma olhada mostra, depois olhe de novo**. Não declare pronto sem ter visto.

---
Fontes estudadas (conteúdo reescrito, não copiado): [Front-End Design Checklist](https://github.com/thedaviddias/Front-End-Design-Checklist) (CC0), [taste-skill](https://github.com/Leonxlnx/taste-skill) (MIT), [impeccable](https://github.com/pbakaus/impeccable) (Apache-2.0), [animate.css](https://github.com/animate-css/animate.css) (Hippocratic License 2.1).
