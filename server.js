import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "chave_super_secreta";

// ======================
// MIDDLEWARES
// ======================
app.use(express.json());

app.use(
  cors({
    origin: [
      "https://agenda-pj.vercel.app",
      "http://localhost:5173"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// ======================
// ROTA TESTE
// ======================
app.get("/", (req, res) => {
  res.json({ status: "API ONLINE 🚀" });
});

// ======================
// LOGIN
// ======================
app.post("/login", async (req, res) => {
  try {
    const { login, password } = req.body;

    if (!login || !password) {
      return res.status(400).json({ error: "Login e senha são obrigatórios" });
    }

    const user = await prisma.usuarios.findFirst({
      where: {
        OR: [{ email: login }, { name: login }],
      },
    });

    if (!user) {
      return res.status(401).json({ error: "Usuário ou senha inválidos" });
    }

    const senhaValida = await bcrypt.compare(password, user.password);
    if (!senhaValida) {
      return res.status(401).json({ error: "Usuário ou senha inválidos" });
    }

    const accessToken = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Remove a senha do retorno
    const { password: _, ...usuarioSemSenha } = user;

    return res.status(200).json({
      accessToken,
      refreshToken,
      usuario: usuarioSemSenha,
    });

  } catch (error) {
    console.error("ERRO NO LOGIN:", error);
    return res.status(500).json({ error: "Erro interno no servidor" });
  }
});

// ======================
// MIDDLEWARE DE TOKEN
// ======================
function autenticarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token não informado" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido ou expirado" });
    }

    req.user = user;
    next();
  });
}

// ======================
// ROTA PROTEGIDA (TESTE)
// ======================
app.get("/perfil", autenticarToken, async (req, res) => {
  try {
    const usuario = await prisma.usuarios.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        name: true,
        email: true,
      },
    });

    res.json(usuario);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar perfil" });
  }
});

// ======================
// START SERVER
// ======================
app.listen(PORT, () => {
  console.log(`🔥 Servidor rodando na porta ${PORT}`);
});
