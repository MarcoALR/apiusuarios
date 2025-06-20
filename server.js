import express from "express";
import { PrismaClient } from "@prisma/client";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();

const prisma = new PrismaClient({
  errorFormat: "pretty",
  log: ["warn", "error"],
});

const app = express();

const corsOptions = {
  origin: [
    "https://agenda-pj.vercel.app",
    "http://localhost:3000",
    "http://localhost",
  ],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// Configuração do transporter do nodemailer com Gmail
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_FROM,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware para autenticar token
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

// Rota para criar usuário
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

    // Enviar e-mail de boas-vindas
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: user.email,
      subject: "Bem-vindo ao Agenda PJ!",
      html: `
        <h2>Olá ${user.name},</h2>
        <p>Seu cadastro foi realizado com sucesso no sistema <strong>Agenda PJ</strong>.</p>
        <p>Agora você pode acessar com seu e-mail e senha cadastrados.</p>
        <br/>
        <p style="color:#888;">Mensagem automática do sistema Agenda PJ</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Email de boas-vindas enviado para: ${user.email}`);

    res.status(201).json(user);
  } catch (err) {
    if (err.code === "P2002" && err.meta?.target?.includes("email")) {
      return res.status(409).json({ error: "E-mail já cadastrado." });
    }

    console.error("Erro ao criar usuário:", err);
    res.status(500).json({ error: "Erro interno ao criar usuário." });
  }
});

// Resto das rotas (login, usuários, refresh token, deletar, etc)
app.post("/login", async (req, res) => {
  const { login, password } = req.body;

  const user = await prisma.usuarios.findFirst({
    where: {
      OR: [{ email: login }, { name: login }],
    },
  });

  if (!user) {
    return res.status(401).json({ error: "Email ou senha inválidos" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).json({ error: "Email ou senha inválidos" });
  }

  const accessToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "1h",
  });

  const refreshToken = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.status(200).json({ accessToken, refreshToken, usuario: user });
});

app.get("/usuarios", autenticaToken, async (req, res) => {
  const users = await prisma.usuarios.findMany();
  res.status(200).json(users);
});

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

app.delete("/usuarios/:id", autenticaToken, async (req, res) => {
  try {
    await prisma.usuarios.delete({
      where: { id: req.params.id },
    });
    res.status(200).json({ message: "Usuário deletado com sucesso!" });
  } catch (err) {
    res.status(500).json({ error: "Erro ao deletar usuário." });
  }
});

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

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
