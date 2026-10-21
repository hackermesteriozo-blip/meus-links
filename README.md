# MatrysArts PRO — loja com contas e chat em tempo real

## Incluído
- Cadastro e login com senha armazenada como hash bcrypt.
- Sessão em cookie `HttpOnly` (não salva a senha no navegador).
- Chat público em tempo real com Socket.IO.
- Chat privado entre contas e conversa com dono/administradores.
- Pedidos guardados no SQLite.
- Painel de pedidos para administradores/dono por API.
- Ranking público calculado apenas com pedidos marcados como `paid` ou `completed`.
- Limite de tentativas no login/cadastro e cabeçalhos de segurança básicos.

## Requisitos
- Node.js 20 ou mais recente.
- Para `better-sqlite3`, use uma versão de Node compatível com binários pré-compilados ou ferramentas de compilação instaladas.

## Instalação local (Windows)
1. Instale Node.js 20+.
2. Extraia este ZIP para uma pasta.
3. Abra o terminal nessa pasta e execute:
   ```bash
   npm install
   ```
4. Copie `.env.example` para `.env`.
5. Abra `.env` e configure `JWT_SECRET`, `OWNER_EMAIL` e `OWNER_PASSWORD`. A senha do dono precisa ter pelo menos 12 caracteres. Nunca publique o `.env`.
6. Execute:
   ```bash
   npm start
   ```
7. Acesse `http://localhost:3000`.

## Como funciona a conta do dono
A primeira inicialização cria a conta de fundador se `OWNER_EMAIL` e `OWNER_PASSWORD` estiverem configurados e a conta ainda não existir. A função não cria uma senha padrão pública. Guarde a senha em local seguro.

## Chat
- Todos os usuários autenticados podem participar do chat público.
- O chat privado usa uma sala criada pelo servidor para os dois IDs escolhidos.
- Para falar com o dono, selecione a conta marcada como `owner` ou `admin` na lista de pessoas.
- Não use o chat para enviar senhas, dados bancários ou informações sensíveis.

## Pedidos e ranking
O cliente precisa estar logado para registrar um pedido no site. Os pedidos entram como `pending`. Um administrador precisa confirmar o pagamento e marcar o pedido como `paid` ou `completed`; só então ele entra no ranking. A API de pedido recebe valores enviados pelo cliente, então os preços finais devem ser validados pelo dono antes de qualquer cobrança.

## Publicação
**GitHub Pages não executa Node.js nem Socket.IO no servidor.** Para ter contas reais e chat ao vivo, publique este projeto inteiro em um host Node.js (por exemplo, Render, Railway ou VPS). Configure as variáveis do `.env` no painel do host e use HTTPS. A pasta `data/` precisa ficar em armazenamento persistente, pois contém o banco SQLite.

## Limitações importantes
- Este pacote não processa pagamento automaticamente nem confirma Pix sozinho. Integração real com Mercado Pago/Stripe exige credenciais privadas e webhook verificado no servidor.
- Antes de abrir ao público, implemente verificação de e-mail, recuperação de senha, política de privacidade/termos, moderação/denúncia de chat, backups e proteção anti-spam adicional.
- O chat privado é acessível pelos participantes da sala; o servidor controla a sala e o histórico é consultado pela API autenticada. Para implantação comercial, faça revisão de segurança independente.


## Música de fundo MP3
- Coloque sua música em `public/music/musica.mp3`.
- O controle fixo no canto inferior esquerdo toca a música quando o visitante clicar em **▶ Música**.
- Também há um botão **🎵 MP3** para escolher um arquivo do computador; essa seleção é local e só vale para aquele navegador/sessão.
- Para disponibilizar a mesma música para todos, coloque o arquivo em `public/music/musica.mp3` e publique novamente.
- Navegadores bloqueiam reprodução automática com som; por isso é necessário clicar para iniciar. Use apenas áudio que você tenha autorização para publicar.
