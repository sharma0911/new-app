import { createHmac } from 'crypto';

// Global variable to store webhook data (will reset on server restart)
// In production, use a database instead
let webhookEvents = [];

// Replace with your actual signing key from Periskope
const SHARED_SECRET = "YOUR_SIGNING_SECRET";

/**
 * Verify the signature from Periskope
 */
function verifySignature(body, signature) {
  const hmac = createHmac("sha256", SHARED_SECRET);
  hmac.update(JSON.stringify(body));
  const digest = hmac.digest("hex");
  return digest === signature;
}

export default function handler(req, res) {
  // Only allow POST requests for webhook
  if (req.method === 'POST') {
    try {
      // Get signature from header
      const signature = req.headers["x-periskope-signature"];
      
      if (!signature) {
        return res.status(400).json({ error: 'Missing signature header' });
      }

      // Verify signature
      const isValid = verifySignature(req.body, signature);
      
      if (!isValid) {
        return res.status(401).json({ error: 'Invalid signature' });
      }

      // Store the webhook data (adding timestamp if not present)
      const webhookData = {
        ...req.body,
        receivedAt: new Date().toISOString()
      };
      
      // Store at the beginning of array (newest first)
      webhookEvents.unshift(webhookData);
      
      // Keep only the last 100 events
      if (webhookEvents.length > 100) {
        webhookEvents = webhookEvents.slice(0, 100);
      }
      
      console.log("Received webhook:", webhookData.event);
      
      return res.status(200).json({ success: true });
    } catch (error) {
      console.error("Error processing webhook:", error);
      return res.status(500).json({ error: 'Server error' });
    }
  } 
  // GET requests to see the stored data
  else if (req.method === 'GET') {
    return res.status(200).json(webhookEvents);
  } 
  else {
    res.setHeader('Allow', ['POST', 'GET']);
    return res.status(405).json({ error: `Method ${req.method} not allowed` });
  }
}
