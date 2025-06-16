import express from "express";
import { PrismaClient } from "@prisma/client";
import cors from 'cors';

const prisma = new PrismaClient();
const app = express();

app.use(cors()); // Permite requisições de outros domínios
app.use(express.json());

// POST - Cria um novo usuário
app.post("/usuarios", async (req, res) => {
  try {
    const user = await prisma.usuarios.create({
      data: {
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
      },
    });
    res.status(201).json(user);
  } catch (err) {
    res.status(500).json({ error: "Erro ao criar usuário." });
  }
});

// GET - Lista todos os usuários
app.get("/usuarios", async (req, res) => {
  const users = await prisma.usuarios.findMany();
  res.status(200).json(users);
});

// PUT - Atualiza um usuário
app.put("/usuarios/:id", async (req, res) => {
  try {
    const updatedUser = await prisma.usuarios.update({
      where: {
        id: req.params.id,
      },
      data: {
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
      },
    });
    res.status(200).json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: "Erro ao atualizar usuário." });
  }
});

// DELETE - Deleta um usuário
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

// POST - LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.usuarios.findFirst({
    where: {
      email,
      password,
    },
  });

  if (!user) {
    return res.status(401).json({ error: "Email ou senha inválidos" });
  }

  res.status(200).json({ user });
});

app.listen(3000, () => {
  console.log("Servidor rodando em http://localhost:3000");
});

/* 
configurar o bamco de dados do mongo db
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

toda vez que salva esse arquivo ele restartar o projeto novamente
'node server.js' usando o comando " node --watch server.js "
*/
