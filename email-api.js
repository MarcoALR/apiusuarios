import express from "express";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(express.json());

// Configuração do Nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_FROM,
    pass: process.env.EMAIL_PASS, // Certifica-te que usas a Senha de App de 16 dígitos
  },
});

// TESTE DE LIGAÇÃO: Verifica se o Gmail aceita as credenciais ao iniciar
transporter.verify((error, success) => {
  if (error) {
    console.error("❌ ERRO NO GMAIL: Verifica EMAIL_FROM e EMAIL_PASS no .env");
    console.error(error.message);
  } else {
    console.log("✅ Servidor de e-mail pronto para uso!");
  }
});

const JWT_SECRET = process.env.JWT_SECRET;

// Middleware de Autenticação
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

// ROTA COM AWAIT: Só responde ao frontend quando o e-mail for enviado
app.post("/send-email", autenticaToken, async (req, res) => {
  const { to, subject, message } = req.body;

  if (!to || !subject || !message) {
    return res.status(400).json({ error: "Dados em falta (to, subject, message)." });
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
    // O await faz o código esperar a confirmação real do Gmail
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email enviado com sucesso para: ${to}`);
    
    return res.status(200).json({ 
      message: "Email enviado com sucesso!", 
      id: info.messageId 
    });

  } catch (error) {
    console.error("❌ ERRO AO ENVIAR EMAIL:");
    console.error("Mensagem:", error.message);

    return res.status(500).json({ 
      error: "Falha ao enviar e-mail.", 
      detalhe: error.message 
    });
  }
});

const port = process.env.PORT_EMAIL || 4000;
app.listen(port, () => {
  console.log(`📧 API de Email a correr na porta ${port}`);
});