import express from "express";
import { PrismaClient } from "@prisma/client";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
app.use(express.json());

// CORS: Configurado corretamente sem barras finais para evitar erro 404/Preflight
app.use(cors({
  origin: [
    "https://agenda-pj.vercel.app",
    "http://localhost:5173"
  ],
  credentials: true,
}));

const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET não definido no .env");
  process.exit(1);
}

// Configuração do Nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_FROM,
    pass: process.env.EMAIL_PASS,
  },
});

transporter.verify((error) => {
  if (error) {
    console.error("❌ Erro na conexão de e-mail:", error);
  } else {
    console.log("✅ E-mail pronto para uso.");
  }
});

// Middleware de Autenticação
function autenticaToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token não enviado" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido ou expirado" });
  }
}

// --- ROTAS ---

app.post("/usuarios", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.usuarios.create({
      data: { name, email, password: hashedPassword },
    });

    res.status(201).json({ user, message: "Usuário criado com sucesso!" });
  } catch (err) {
    if (err.code === "P2002") {
      return res.status(409).json({ error: "E-mail já cadastrado." });
    }
    res.status(500).json({ error: "Erro ao criar usuário." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { login, password } = req.body;

    const user = await prisma.usuarios.findFirst({
      where: { OR: [{ email: login }, { name: login }] },
    });

    if (!user) return res.status(401).json({ error: "Email ou senha inválidos" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Email ou senha inválidos" });

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

    // Retorna 'token' e 'accessToken' para garantir compatibilidade com o frontend
    res.json({
      token: accessToken, 
      accessToken,
      refreshToken,
      usuario: { id: user.id, name: user.name, email: user.email }
    });
  } catch (err) {
    res.status(500).json({ error: "Erro ao realizar login." });
  }
});

app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: "Refresh token não enviado" });

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const newAccessToken = jwt.sign(
      { id: decoded.id, email: decoded.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token: newAccessToken, accessToken: newAccessToken });
  } catch {
    res.status(401).json({ error: "Refresh token inválido ou expirado" });
  }
});

app.get("/validate-token", autenticaToken, (req, res) => {
  res.status(200).json({ valid: true, userId: req.user.id });
});

app.get("/usuarios", autenticaToken, async (req, res) => {
  try {
    const users = await prisma.usuarios.findMany({
      select: { id: true, name: true, email: true } // Não retorna as senhas
    });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Erro ao listar usuários." });
  }
});

app.put("/usuarios/:id", autenticaToken, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const data = { name, email };

    if (password) {
      data.password = await bcrypt.hash(password, 10);
    }

    const updated = await prisma.usuarios.update({
      where: { id: req.params.id },
      data,
    });

    res.json(updated);
  } catch {
    res.status(500).json({ error: "Erro ao atualizar usuário." });
  }
});

app.delete("/usuarios/:id", autenticaToken, async (req, res) => {
  try {
    await prisma.usuarios.delete({
      where: { id: req.params.id },
    });
    res.json({ message: "Usuário deletado com sucesso!" });
  } catch {
    res.status(500).json({ error: "Erro ao deletar usuário." });
  }
});

// ENVIO DE E-MAIL EM BACKGROUND: Corrigido para ser rápido e não travar o fluxo
app.post("/enviar-email", autenticaToken, async (req, res) => {
  const { to, subject, message } = req.body;
  if (!to || !subject || !message) {
    return res.status(400).json({ error: "Campos obrigatórios faltando." });
  }

  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to,
    subject,
    html: `<div style="font-family: Arial;">${message}</div>`,
  };

  // Dispara o envio e responde imediatamente ao frontend
  transporter.sendMail(mailOptions)
    .then(info => console.log("📧 E-mail enviado com sucesso:", info.messageId))
    .catch(err => console.error("❌ Erro ao enviar e-mail em background:", err));

  res.json({ message: "Processo de envio iniciado." });
});

// Inicialização do servidor
const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log(`🚀 Servidor rodando na porta ${port}`);
});