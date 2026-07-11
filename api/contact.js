// Vercel Serverless Function: /api/contact
// Empfängt das Kontaktformular von voris.eu und versendet die Anfrage per Resend.
//
// Einrichtung in Vercel:
//   Project Settings → Environment Variables:
//     RESEND_API_KEY  = re_xxxxxxxx        (dein Resend API-Key)
//     CONTACT_TO       = voris@pan21.com    (optional, Default unten)
//     CONTACT_FROM     = "VORIS Website <website@pan21.com>"  (Domain muss bei Resend verifiziert sein)
//
// Der API-Key steht NUR hier serverseitig in der Umgebung – niemals im Frontend.

const TO_ADDRESS = process.env.CONTACT_TO || "voris@pan21.com";
const FROM_ADDRESS = process.env.CONTACT_FROM || "VORIS Website <website@pan21.com>";

// Einfacher In-Memory-Rate-Limiter pro IP (greift innerhalb einer warmen Instanz).
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 Minute
const RATE_LIMIT_MAX = 3; // max. 3 Anfragen pro Minute und IP
const hits = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const entry = hits.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_LIMIT_WINDOW_MS) {
    entry.count = 0;
    entry.start = now;
  }
  entry.count += 1;
  hits.set(ip, entry);
  return entry.count > RATE_LIMIT_MAX;
}

function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v || "");

// Catches bot-generated random tokens that are short enough to slide past a simple
// length check but look nothing like a real word: very few vowels AND unnaturally
// frequent upper/lowercase switching. Both conditions required together to avoid
// flagging real oddly-cased words (e.g. "McDonald").
function isGibberish(str) {
  const words = (str || '').split(/\s+/).filter(w => w.length >= 6);
  const vowelChars = 'aeiouyAEIOUYäöüÄÖÜàáâãåèéêëìíîïòóôõùúûýÀÁÂÃÅÈÉÊËÌÍÎÏÒÓÔÕÙÚÛÝ';
  for (const word of words) {
    const letters = word.replace(/[^a-zA-ZäöüÄÖÜßàáâãåèéêëìíîïòóôõùúûýÀÁÂÃÅÈÉÊËÌÍÎÏÒÓÔÕÙÚÛÝ]/g, '');
    if (letters.length < 6) continue;
    let vowels = 0;
    for (const ch of letters) if (vowelChars.includes(ch)) vowels++;
    const vowelRatio = vowels / letters.length;
    let transitions = 0;
    for (let i = 1; i < letters.length; i++) {
      const prevUpper = letters[i - 1] === letters[i - 1].toUpperCase() && letters[i - 1] !== letters[i - 1].toLowerCase();
      const curUpper = letters[i] === letters[i].toUpperCase() && letters[i] !== letters[i].toLowerCase();
      if (prevUpper !== curUpper) transitions++;
    }
    const transitionRatio = transitions / (letters.length - 1);
    // Tiered threshold: longer strings need a less extreme vowel-ratio to be flagged,
    // since genuine long words (esp. German compounds) always carry a healthy vowel
    // share, while short strings need a stricter cutoff to avoid catching real
    // camelCase brand names (McDonald, PayPal, JavaScript...).
    const vowelThreshold = letters.length >= 14 ? 0.28 : (letters.length >= 11 ? 0.22 : 0.16);
    if (vowelRatio < vowelThreshold && transitionRatio > 0.3) return true;
  }
  if (/\S{61,}/.test(str || '')) return true;
  return false;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  if (!process.env.RESEND_API_KEY) {
    return res.status(500).json({ ok: false, error: "Server not configured" });
  }

  // Body parsen (Vercel parst JSON i.d.R. automatisch; Fallback für Strings)
  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  body = body || {};

  const {
    name = "",
    email = "",
    phone = "",
    subject = "",
    message = "",
    // Spam-Schutz-Felder:
    company = "", // Honeypot: muss leer bleiben (für Menschen unsichtbar)
    ts = "",      // Zeitstempel: wann das Formular geladen wurde
  } = body;

  // Gibberish-Bot-Erkennung (kurze Zufallsstrings) — silent success wie Honeypot
  if (isGibberish(message) || isGibberish(name)) { return res.status(200).json({ ok: true }); }

  // --- Spam-Schutz -------------------------------------------------------
  // 1) Honeypot: Bots füllen versteckte Felder aus.
  if (company && String(company).trim() !== "") {
    return res.status(200).json({ ok: true }); // still verwerfen, kein Hinweis an Bot
  }

  // 2) Timing-Falle: Echte Nutzer brauchen länger als ~3 Sekunden.
  const elapsed = Date.now() - Number(ts || 0);
  if (!ts || isNaN(elapsed) || elapsed < 3000) {
    return res.status(200).json({ ok: true }); // verdächtig schnell → verwerfen
  }

  // 3) Rate Limiting pro IP
  const ip =
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    "unknown";
  if (isRateLimited(ip)) {
    return res.status(429).json({ ok: false, error: "Zu viele Anfragen. Bitte später erneut versuchen." });
  }

  // --- Validierung -------------------------------------------------------
  const cleanName = String(name).trim().slice(0, 200);
  const cleanEmail = String(email).trim().slice(0, 200);
  const cleanPhone = String(phone).trim().slice(0, 100);
  const cleanSubject = String(subject).trim().slice(0, 200) || "Allgemeine Anfrage";
  const cleanMessage = String(message).trim().slice(0, 5000);

  if (!cleanName || !isEmail(cleanEmail) || !cleanMessage) {
    return res.status(400).json({ ok: false, error: "Bitte Name, gültige E-Mail und Nachricht angeben." });
  }

  // --- E-Mail zusammenbauen ---------------------------------------------
  const html = `
    <h2>Neue Kontaktanfrage über voris.eu</h2>
    <table cellpadding="6" style="border-collapse:collapse;font-family:sans-serif;font-size:14px">
      <tr><td><strong>Name</strong></td><td>${escapeHtml(cleanName)}</td></tr>
      <tr><td><strong>E-Mail</strong></td><td>${escapeHtml(cleanEmail)}</td></tr>
      <tr><td><strong>Telefon</strong></td><td>${escapeHtml(cleanPhone || "—")}</td></tr>
      <tr><td><strong>Betreff</strong></td><td>${escapeHtml(cleanSubject)}</td></tr>
      <tr><td valign="top"><strong>Nachricht</strong></td><td>${escapeHtml(cleanMessage).replace(/\n/g, "<br>")}</td></tr>
    </table>
  `;

  const text =
    `Neue Kontaktanfrage über voris.eu\n\n` +
    `Name: ${cleanName}\n` +
    `E-Mail: ${cleanEmail}\n` +
    `Telefon: ${cleanPhone || "—"}\n` +
    `Betreff: ${cleanSubject}\n\n` +
    `Nachricht:\n${cleanMessage}\n`;

  // --- Versand über Resend ----------------------------------------------
  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: FROM_ADDRESS,
        to: [TO_ADDRESS],
        reply_to: cleanEmail, // Antworten gehen direkt an den Besucher
        subject: "Kontaktanfrage VORIS KG",
        html,
        text,
      }),
    });

    if (!resp.ok) {
      const detail = await resp.text();
      console.error("Resend error:", resp.status, detail);
      return res.status(502).json({ ok: false, error: "E-Mail konnte nicht versendet werden." });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("Send failure:", err);
    return res.status(500).json({ ok: false, error: "Unerwarteter Fehler." });
  }
}
