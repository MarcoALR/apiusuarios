import express from "express";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(express.json());

const transporter = process.env.EMAIL_FROM && process.env.EMAIL_PASS
  ? nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_FROM,
        pass: process.env.EMAIL_PASS,
      },
    })
  : null;

const JWT_SECRET = process.env.JWT_SECRET;

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

// ROTA OTIMIZADA: Agora ela não espera o Gmail responder
app.post("/send-email", autenticaToken, (req, res) => {
  const { to, subject, message } = req.body;

  if (!transporter) {
    return res.status(500).json({ error: "Transporte de email não configurado." });
  }

  if (!to || !subject || !message) {
    return res.status(400).json({ error: "Campos obrigatórios: to, subject, message." });
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

  // 1. DISPARAMOS O ENVIO (sem await)
  transporter.sendMail(mailOptions)
    .then(info => console.log(`✅ Email enviado em background para ${to}`))
    .catch(error => console.error("❌ Erro no envio silencioso:", error));

  // 2. RESPONDEMOS AO USUÁRIO NA HORA
  // O Frontend recebe o OK em milissegundos
  res.status(200).json({ 
    message: "Solicitação de envio recebida! O email será processado em background." 
  });
});

const port = process.env.PORT_EMAIL || 4000;
app.listen(port, () => {
  console.log(`📧 Email API rodando na porta ${port}`);
});