require('dotenv').config();

console.log('🔍 Environment check:');
console.log('  GMAIL_USER:', process.env.GMAIL_USER ? '✅ Set to ' + process.env.GMAIL_USER : '❌ Missing');
console.log('  WEBHOOK_SECRET:', process.env.WEBHOOK_SECRET ? '✅ Set' : '❌ Missing');
console.log('  EBOOK_PATH:', process.env.EBOOK_PATH ? '✅ Set' : '❌ Missing');
console.log('  GMAIL_APP_PASSWORD:', process.env.GMAIL_APP_PASSWORD ? '✅ Set' : '❌ Missing');

const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Track processed orders to prevent duplicate emails ───────────────────────
const processedOrders = new Set();

// ─── Raw body needed for HMAC signature verification ──────────────────────────
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// ─── Email transporter — Gmail port 465 (SSL, works on Render) ───────────────
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

transporter.verify((err) => {
  if (err) {
    console.error('❌ SMTP connection failed:', err.message);
  } else {
    console.log('✅ SMTP ready');
  }
});

// ─── Fetch PDF from URL and return as buffer ──────────────────────────────────
function fetchPDF(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        return fetchPDF(response.headers.location).then(resolve).catch(reject);
      }
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', reject);
    }).on('error', reject);
  });
}

// ─── Signature verification (Suby.fi) ────────────────────────────────────────
function verifySignature(req) {
  const signatureHeader = req.headers['x-webhook-signature'];
  const timestamp = req.headers['x-webhook-timestamp'];

  if (!signatureHeader || !timestamp) {
    console.warn('Missing signature or timestamp headers');
    return false;
  }

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp)) > 300) {
    console.warn('Webhook timestamp too old');
    return false;
  }

  const signatureMatch = signatureHeader.match(/^v1=([a-f0-9]+)$/);
  if (!signatureMatch) {
    console.warn('Invalid signature header format');
    return false;
  }

  const signedPayload = `${timestamp}.${req.rawBody.toString()}`;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET)
    .update(signedPayload)
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(signatureMatch[1]),
    Buffer.from(expectedSignature)
  );
}

// ─── Webhook endpoint ─────────────────────────────────────────────────────────
app.post('/webhook', async (req, res) => {
  if (!verifySignature(req)) {
    console.warn('⚠️  Invalid webhook signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = req.body;
  const eventType = req.headers['x-webhook-event'];
  const paymentId = event.data?.payment?.id;

  console.log(`📨 Received webhook: ${eventType} - Payment: ${paymentId}`);

  if (processedOrders.has(paymentId)) {
    console.log(`⚠️  Payment ${paymentId} already processed, skipping`);
    return res.status(200).json({ status: 'already_processed' });
  }

  switch (eventType) {
    case 'CHECKOUT_SUCCESS':
    case 'TX_SUCCESS': {
      const customerEmail = event.data?.payment?.customerEmail;

      if (!customerEmail || !paymentId) {
        console.error('❌ Missing email or paymentId');
        return res.status(400).json({ error: 'Missing fields' });
      }

      processedOrders.add(paymentId);

      try {
        // Fetch the PDF from Google Drive
        console.log('📥 Fetching ebook PDF...');
        const pdfBuffer = await fetchPDF(process.env.EBOOK_PATH);
        console.log(`📄 PDF fetched — ${Math.round(pdfBuffer.length / 1024)}KB`);

        // 1. Send ebook to customer
        await transporter.sendMail({
          from: `"${process.env.STORE_NAME}" <${process.env.GMAIL_USER}>`,
          to: customerEmail,
          subject: `Your "${process.env.EBOOK_TITLE}" download is ready!`,
          html: `
            <p>Hi there,</p>
            <p>Thank you for your purchase! Your ebook <strong>${process.env.EBOOK_TITLE}</strong> is attached.</p>
            <p>Payment ID: <code>${paymentId}</code></p>
            <p>Enjoy the read! 📚</p>
          `,
          attachments: [
            {
              filename: process.env.EBOOK_FILENAME,
              content: pdfBuffer,
            },
          ],
        });

        console.log(`✅ Customer email sent to: ${customerEmail}`);

        // 2. Notify admin
        await transporter.sendMail({
          from: `"${process.env.STORE_NAME}" <${process.env.GMAIL_USER}>`,
          to: process.env.ADMIN_EMAIL,
          subject: `💰 NEW SALE: ${process.env.EBOOK_TITLE}`,
          html: `
            <h2>New Payment Received!</h2>
            <table style="border-collapse:collapse;width:100%">
              <tr><td style="padding:8px;border:1px solid #ddd"><strong>Payment ID</strong></td><td style="padding:8px;border:1px solid #ddd">${paymentId}</td></tr>
              <tr><td style="padding:8px;border:1px solid #ddd"><strong>Customer</strong></td><td style="padding:8px;border:1px solid #ddd">${customerEmail}</td></tr>
              <tr><td style="padding:8px;border:1px solid #ddd"><strong>Product</strong></td><td style="padding:8px;border:1px solid #ddd">${process.env.EBOOK_TITLE}</td></tr>
              <tr><td style="padding:8px;border:1px solid #ddd"><strong>Time</strong></td><td style="padding:8px;border:1px solid #ddd">${new Date().toLocaleString()}</td></tr>
            </table>
          `,
        });

        console.log('✅ Admin notified');
        return res.status(200).json({ status: 'ok', paymentId });

      } catch (err) {
        console.error('❌ Failed to send email:', err.message);
        processedOrders.delete(paymentId);
        return res.status(500).json({ error: 'Email delivery failed' });
      }
    }

    default:
      console.log(`ℹ️  Unhandled event type: ${eventType}`);
      return res.status(200).json({ status: 'ignored' });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── Start ────────────────────────────────────────────────────────────────────
const server = app.listen(PORT, () =>
  console.log(`🚀 Webhook server listening on port ${PORT}`)
);

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  server.close(() => process.exit(0));
});
