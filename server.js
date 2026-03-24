require('dotenv').config();

// DEBUG: Check environment variables are loading
console.log('🔍 Environment check:');
console.log('  GMAIL_USER:', process.env.GMAIL_USER ? '✅ Set to ' + process.env.GMAIL_USER : '❌ Missing');
console.log('  WEBHOOK_SECRET:', process.env.WEBHOOK_SECRET ? '✅ Set' : '❌ Missing');
console.log('  EBOOK_PATH:', process.env.EBOOK_PATH ? '✅ Set' : '❌ Missing');

const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

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

// ─── Email transporter ────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // Use STARTTLS (not SSL)
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
  tls: {
    // Do not fail on invalid certs
    rejectUnauthorized: false
  }
});

// Verify SMTP connection on startup with better error logging
transporter.verify((err) => {
  if (err) {
    console.error('❌ SMTP connection failed:', err.message);
    console.error('📧 GMAIL_USER:', process.env.GMAIL_USER ? 'Set' : 'Missing');
    console.error('🔑 GMAIL_APP_PASSWORD:', process.env.GMAIL_APP_PASSWORD ? 'Set' : 'Missing');
  } else {
    console.log('✅ SMTP ready');
  }
});

// ─── Signature verification helper ───────────────────────────────────────────
// ─── Signature verification helper (Updated for Suby.fi) ───────────────────
function verifySignature(req) {
  const signatureHeader = req.headers['x-webhook-signature'];
  const timestamp = req.headers['x-webhook-timestamp'];
  
  if (!signatureHeader || !timestamp) {
    console.warn('Missing signature or timestamp headers');
    return false;
  }
  
  // Check timestamp is not older than 5 minutes (300 seconds)
  const now = Math.floor(Date.now() / 1000);
  const timestampNum = parseInt(timestamp);
  if (Math.abs(now - timestampNum) > 300) {
    console.warn('Webhook timestamp too old, possible replay attack');
    return false;
  }
  
  // Format: "v1=hexdigest"
  const signatureMatch = signatureHeader.match(/^v1=([a-f0-9]+)$/);
  if (!signatureMatch) {
    console.warn('Invalid signature header format');
    return false;
  }
  
  const receivedSignature = signatureMatch[1];
  
  // Create expected signature: HMAC-SHA256(timestamp.rawBody)
  const signedPayload = `${timestamp}.${req.rawBody.toString()}`;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET)
    .update(signedPayload)
    .digest('hex');
  
  // Use timing-safe comparison
  return crypto.timingSafeEqual(
    Buffer.from(receivedSignature),
    Buffer.from(expectedSignature)
  );
}

// ─── Webhook endpoint ─────────────────────────────────────────────────────────
app.post('/webhook', async (req, res) => {
  // 1. Verify signature
  if (!verifySignature(req)) {
    console.warn('⚠️ Invalid webhook signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = req.body;
  const eventType = req.headers['x-webhook-event'];
  const paymentId = event.data?.payment?.id;
  
  console.log(`📨 Received webhook: ${eventType} - Payment: ${paymentId}`);

  // ✅ CHECK DUPLICATE FIRST - Before any processing
  if (processedOrders.has(paymentId)) {
    console.log(`⚠️ Payment ${paymentId} already processed, skipping`);
    return res.status(200).json({ status: 'already_processed' });
  }

  // Handle different event types
  switch (eventType) {
    case 'CHECKOUT_SUCCESS':
    case 'TX_SUCCESS':
      const customerEmail = event.data?.payment?.customerEmail;
      
      if (!customerEmail || !paymentId) {
        console.error('❌ Missing email or paymentId');
        return res.status(400).json({ error: 'Missing fields' });
      }
      
      // ✅ MARK AS PROCESSED IMMEDIATELY - Before sending emails
      processedOrders.add(paymentId);
      
      // Send emails (both customer and admin)
      try {
        // 1. Send email to customer with ebook attachment
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
              path: process.env.EBOOK_PATH,
            },
          ],
        });
        
        console.log(`✅ Customer email sent to: ${customerEmail}`);
        
        // 2. Send admin notification
        await transporter.sendMail({
          from: `"${process.env.STORE_NAME}" <${process.env.GMAIL_USER}>`,
          to: process.env.ADMIN_EMAIL,
          subject: `💰 NEW SALE: ${process.env.EBOOK_TITLE}`,
          html: `
            <h2>💰 New Payment Received!</h2>
            <table style="border-collapse: collapse; width: 100%;">
              <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Payment ID:</strong></td>
                  <td style="padding: 8px; border: 1px solid #ddd;">${paymentId}</td></tr>
              <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Customer:</strong></td>
                  <td style="padding: 8px; border: 1px solid #ddd;">${customerEmail}</td></tr>
              <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Product:</strong></td>
                  <td style="padding: 8px; border: 1px solid #ddd;">${process.env.EBOOK_TITLE}</td></tr>
              <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Event Type:</strong></td>
                  <td style="padding: 8px; border: 1px solid #ddd;">${eventType}</td></tr>
              <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Time:</strong></td>
                  <td style="padding: 8px; border: 1px solid #ddd;">${new Date().toLocaleString()}</td></tr>
             </table>
            <p style="color: #666; font-size: 12px;">This is an automated notification.</p>
          `,
        });
        
        console.log(`✅ Admin notified`);
        
        // ✅ Send immediate success response
        return res.status(200).json({ status: 'ok', paymentId });
        
      } catch (err) {
        console.error('❌ Failed to send email:', err.message);
        // If email fails, remove from processed set so next retry will work
        processedOrders.delete(paymentId);
        return res.status(500).json({ error: 'Email delivery failed' });
      }
      
    default:
      console.log(`ℹ️ Unhandled event type: ${eventType}`);
      return res.status(200).json({ status: 'ignored' });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── Start ────────────────────────────────────────────────────────────────────
const server = app.listen(PORT, () =>
  console.log(`🚀 Webhook server listening on port ${PORT}`)
);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  server.close(() => process.exit(0));
});
