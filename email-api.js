import express from "express";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

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

app.post("/send-email", async (req, res) => {
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

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Erro ao enviar email:", error);
      res.status(500).json({ error: "Erro ao enviar email." });
    } else {
      console.log(`✅ Email enviado para ${to}`);
      res.status(200).json({ message: "Email enviado com sucesso!", info });
    }
  });
});

const port = process.env.PORT_EMAIL || 4000;
app.listen(port, () => {
  console.log(`📧 Email API rodando na porta ${port}`);
});
