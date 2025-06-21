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

const corsOptions = {
  origin: [
    "https://agenda-pj.vercel.app",
    "http://localhost:3000",
    "http://localhost"
  ],
};
app.use(cors(corsOptions));

const prisma = new PrismaClient({
  errorFormat: "pretty",
  log: ["warn", "error"],
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET não definido no .env");
  process.exit(1);
}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_FROM,
    pass: process.env.EMAIL_PASS,
  },
});

transporter.verify((error, success) => {
  if (error) {
    console.error("❌ Falha ao configurar e-mail:", error);
  } else {
    console.log("✅ Transporte de e-mail pronto.");
  }
});
function autenticaToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token não enviado" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido ou expirado" });
  }
}

app.post("/usuarios", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.usuarios.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    res.status(201).json({ user, message: "Usuário criado com sucesso!" });
  } catch (err) {
    if (err.code === "P2002" && err.meta?.target?.includes("email")) {
      return res.status(409).json({ error: "E-mail já cadastrado." });
    }
    console.error("Erro ao criar usuário:", err);
    res.status(500).json({ error: "Erro interno ao criar usuário." });
  }
});

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

app.post("/enviar-email", autenticaToken, async (req, res) => {
  const { to, subject, message } = req.body;

  if (!to || !subject || !message) {
    return res.status(400).json({
      error: "Campos obrigatórios: to, subject e message.",
    });
  }

  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to,
    subject,
    html: `
      <div style="font-family: Arial, sans-serif; font-size:16px;">
        ${message}
      </div>
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ E-mail enviado para: ${to}`);
    res.status(200).json({ message: "E-mail enviado com sucesso!", info });
  } catch (error) {
    console.error("❌ Erro ao enviar e-mail:", error);
    res.status(500).json({ error: "Erro ao enviar e-mail." });
  }
});
app.get("/usuarios", autenticaToken, async (req, res) => {
  const users = await prisma.usuarios.findMany();
  res.status(200).json(users);
});

app.put("/usuarios/:id", autenticaToken, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const data = { name, email };

    if (password) {
      data.password = await bcrypt.hash(password, 10);
    }

    const updatedUser = await prisma.usuarios.update({
      where: { id: req.params.id },
      data,
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
  console.log(`🚀 Servidor rodando na porta ${port}`);
});
