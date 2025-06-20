import express from "express";
import { PrismaClient } from "@prisma/client";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();
const app = express();

const corsOptions = {
  origin: [
    'https://agenda-pj.vercel.app'
  ],
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

const JWT_SECRET =
  "%M75yCMTKDVBFK?&W35%F#fYALQ@Lj9&#zfVXgBBWUZ#?JWy4J78h1J@76Gusp**";

// Middleware de autenticação
function autenticaToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token não enviado" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido ou expirado" });
  }
}

// POST - Cria um novo usuário (senha com hash)
app.post("/usuarios", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const user = await prisma.usuarios.create({
      data: {
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
      },
    });

    res.status(201).json(user);
  } catch (err) {
    res.status(500).json({ error: "Erro ao criar usuário." });
  }
});

// GET - Lista todos os usuários (protegida)
app.get("/usuarios", autenticaToken, async (req, res) => {
  const users = await prisma.usuarios.findMany();
  res.status(200).json(users);
});

// PUT - Atualiza um usuário (protegida) com hash se senha for alterada
app.put("/usuarios/:id", autenticaToken, async (req, res) => {
  try {
    let updatedData = {
      name: req.body.name,
      email: req.body.email,
    };

    if (req.body.password) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      updatedData.password = hashedPassword;
    }

    const updatedUser = await prisma.usuarios.update({
      where: { id: req.params.id },
      data: updatedData,
    });

    res.status(200).json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: "Erro ao atualizar usuário." });
  }
});

// POST - LOGIN com comparação de senha com hash
app.post("/login", async (req, res) => {
  const { login, password } = req.body;

  const user = await prisma.usuarios.findFirst({
    where: {
      OR: [
        { email: login },
        { name: login }
      ]
    }
  });

  if (!user) {
    return res.status(401).json({ error: "Email ou senha inválidos" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).json({ error: "Email ou senha inválidos" });
  }

  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  const refreshToken = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.status(200).json({ accessToken, refreshToken, usuario: user });
});

// GET - Valida o accessToken
app.get("/validate-token", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token não enviado" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.status(200).json({ valid: true, userId: decoded.id });
  } catch (err) {
    res.status(401).json({ error: "Token inválido ou expirado" });
  }
});

// POST - Refresh token endpoint
app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token não enviado" });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);

    const newAccessToken = jwt.sign(
      { id: decoded.id, email: decoded.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(401).json({ error: "Refresh token inválido ou expirado" });
  }
});

app.listen(3000, () => {
  console.log("Servidor rodando em http://localhost:3000");
});

/* 
configurar o banco de dados do mongo db
        mongo db
      usuario: Marco
    senha: L9wvwMTXDuCRAQd7


Sempre que você altera o modelo no schema.prisma 
(como trocar usuario para usuarios, mudar campos, etc.), é obrigatório rodar:
npx prisma db push


mongodb+srv://Marco:"CHAVEDEACESSO"@users.twjeorl.mongodb.net/"NOEMDOBANCO"?retryWrites=true&w=majority&appName=Users

criar a API de listagem de usuarios com => GET POST DELETE PUT 

1)tipo de rota / metodo http  GET POST DELETE PUT PACHT

2)endereço

      ctrl + c para parar o servidor

 configurando o gerenciador do mongo db pelo visual studio code 

 1)npm install prisma --save-dev   
 2)npx prisma init cria os arquivos de configuração do prisma
 3)configurar o banco de dados no arquivo .env   
 4)configurar o arquivo schema.prisma
5) npx prisma db push  //  faz que o @unique funcione O BD É NAO TENHA JEITO DE REPETIR OS EMAILS
6) npm install @prisma/client // instala o cliente do prisma
7) npx prisma studio // abre o banco de dados no navegador
9)
Se os nomes das propriedades no Thunder Client gerenciador estiverem fora do padrão, o backend não aceita.
   data: {
      name: req.body.name,
      email: req.body.email,
      password: req.body.password
}

 Query params GET serve para LISTAR filtrando, paginar e ordenar os dados
  Exemplo: /usuarios?name=Marco&age=30

vou importar o token npm install jsonwebtoken para autenticação
e usar o middleware para proteger as rotas.


npm install bcryptjs isso para criptografar a senha do usuário



toda vez que salva esse arquivo ele restartar o projeto novamente
'node server.js' usando o comando " node --watch server.js "
*/

/*  DELETE - Deleta um usuário
app.delete("/usuarios/:id", async (req, res) => {
  try {
    await prisma.usuarios.delete({
      where: {
        id: req.params.id,
      },
    });
    res.status(200).json({ message: "Usuário deletado com sucesso!" });
  } catch (err) {
    res.status(500).json({ error: "Erro ao deletar usuário." });
  }
});

*/
