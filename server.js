import express from "express";
import { PrismaClient } from "@prisma/client";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
const prisma = new PrismaClient();

/* =======================
   MIDDLEWARES
======================= */
app.use(express.json());

app.use(
  cors({
    origin: [
      "https://agenda-pj.vercel.app",
      "http://localhost:3000",
      "http://localhost",
    ],
    credentials: true,
  })
);

/* =======================
   ROTA RAIZ (OBRIGATÓRIA)
======================= */
app.get("/", (req, res) => {
  res.status(200).send("🚀 API Agenda PJ rodando");
});

/* =======================
   JWT CONFIG
======================= */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET não definido no .env");
  process.exit(1);
}

/* =======================
   EMAIL CONFIG
======================= */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_FROM,
    pass: process.env.EMAIL_PASS,
  },
});

/* =======================
   AUTH MIDDLEWARE
======================= */
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
  } catch {
    return res.status(401).json({ error: "Token inválido ou expirado" });
  }
}

/* =======================
   ROTAS
======================= */

// CADASTRO
app.post("/usuarios", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.usuarios.create({
      data: { name, email, password: hashedPassword },
    });

    res.status(201).json({
      id: user.id,
      name: user.name,
      email: user.email,
    });
  } catch (err) {
    if (err.code === "P2002") {
      return res.status(409).json({ error: "E-mail já cadastrado" });
    }
    res.status(500).json({ error: "Erro ao criar usuário" });
  }
});

// LOGIN (CORRIGIDA)
app.post("/login", async (req, res) => {
  try {
    const { login, password } = req.body;

    if (!login || !password) {
      return res.status(400).json({ error: "Login e senha obrigatórios" });
    }

    const user = await prisma.usuarios.findFirst({
      where: {
        OR: [{ email: login }, { name: login }],
      },
    });

    if (!user) {
      return res.status(401).json({ error: "Usuário ou senha inválidos" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
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

    res.json({
      accessToken,
      refreshToken,
      usuario: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("❌ Erro no login:", error);
    res.status(500).json({ error: "Erro interno no login" });
  }
});

// REFRESH TOKEN
app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token não enviado" });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);

    const newAccessToken = jwt.sign(
      { id: decoded.id },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ accessToken: newAccessToken });
  } catch {
    res.status(401).json({ error: "Refresh token inválido ou expirado" });
  }
});

// VALIDAR TOKEN
app.get("/validate-token", autenticaToken, (req, res) => {
  res.json({ valid: true, userId: req.user.id });
});

// LISTAR USUÁRIOS
app.get("/usuarios", autenticaToken, async (req, res) => {
  const users = await prisma.usuarios.findMany({
    select: { id: true, name: true, email: true },
  });
  res.json(users);
});

// ENVIAR EMAIL
app.post("/enviar-email", autenticaToken, async (req, res) => {
  const { to, subject, message } = req.body;

  if (!to || !subject || !message) {
    return res.status(400).json({ error: "Campos obrigatórios faltando" });
  }

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      html: message,
    });

    res.json({ message: "E-mail enviado com sucesso" });
  } catch (error) {
    console.error("❌ Erro ao enviar e-mail:", error);
    res.status(500).json({ error: "Erro ao enviar e-mail" });
  }
});

/* =======================
   START SERVER
======================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
