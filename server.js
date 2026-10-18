const express = require('express');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error('Set ADMIN_PASSWORD to a strong password of at least 12 characters.');
  process.exit(1);
}
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Set SESSION_SECRET to a random secret of at least 32 characters.');
  process.exit(1);
}

const db = new Database(process.env.DB_FILE || path.join(__dirname, 'imperator.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'player',
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS countries (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, flag TEXT NOT NULL, owner_id INTEGER UNIQUE REFERENCES users(id) ON DELETE SET NULL,
 wealth INTEGER NOT NULL DEFAULT 50, military INTEGER NOT NULL DEFAULT 50, tech INTEGER NOT NULL DEFAULT 50,
 happiness INTEGER NOT NULL DEFAULT 50, stability INTEGER NOT NULL DEFAULT 50
);
CREATE TABLE IF NOT EXISTS actions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, player_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 country_id TEXT NOT NULL REFERENCES countries(id), text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 result TEXT, created_at INTEGER NOT NULL, answered_at INTEGER
);
CREATE TABLE IF NOT EXISTS news (
 id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL, created_at INTEGER NOT NULL,
 author_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);
`);
const countries = [
['ir','ایران','🇮🇷'],['us','آمریکا','🇺🇸'],['ru','روسیه','🇷🇺'],['cn','چین','🇨🇳'],
['gb','انگلستان','🇬🇧'],['fr','فرانسه','🇫🇷'],['de','آلمان','🇩🇪'],['jp','ژاپن','🇯🇵'],
['tr','ترکیه','🇹🇷'],['sa','عربستان','🇸🇦']
];
const addCountry=db.prepare('INSERT OR IGNORE INTO countries(id,name,flag) VALUES(?,?,?)');
for(const c of countries)addCountry.run(...c);

const admin=db.prepare('SELECT id FROM users WHERE username=?').get(ADMIN_USER);
if(!admin){
 const hash=bcrypt.hashSync(ADMIN_PASSWORD,12);
 db.prepare('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)').run(ADMIN_USER,hash,'admin',Date.now());
} else {
 const row=db.prepare('SELECT role FROM users WHERE username=?').get(ADMIN_USER);
 if(row.role!=='admin')db.prepare("UPDATE users SET role='admin' WHERE username=?").run(ADMIN_USER);
}

const app=express();
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'20kb'}));
app.use(session({
 name:'imperator.sid', secret:SESSION_SECRET, resave:false, saveUninitialized:false,
 store:new SQLiteStoreFactory({db:'sessions.sqlite',dir:__dirname}),
 cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:1000*60*60*12}
}));
const authLimit=rateLimit({windowMs:15*60*1000,limit:15,standardHeaders:true,legacyHeaders:false,message:{error:'تلاش‌های زیاد؛ کمی بعد دوباره امتحان کن.'}});
app.use('/api/login',authLimit);app.use('/api/register',authLimit);
const now=()=>Date.now();
const userPublic=u=>({id:u.id,username:u.username,role:u.role});
function requireAuth(req,res,next){if(!req.session.userId)return res.status(401).json({error:'ابتدا وارد حساب شو.'});next()}
function requireAdmin(req,res,next){if(!req.session.userId)return res.status(401).json({error:'ابتدا وارد حساب شو.'});const u=db.prepare('SELECT role FROM users WHERE id=?').get(req.session.userId);if(!u||u.role!=='admin')return res.status(403).json({error:'دسترسی مدیر لازم است.'});next()}
function validText(v,max=3000){return typeof v==='string'&&v.trim().length>0&&v.trim().length<=max}
function stateFor(req){
 const me=req.session.userId?db.prepare('SELECT id,username,role FROM users WHERE id=?').get(req.session.userId):null;
 const allCountries=db.prepare(`SELECT c.*,u.username owner_username FROM countries c LEFT JOIN users u ON u.id=c.owner_id ORDER BY c.name`).all().map(c=>({id:c.id,name:c.name,flag:c.flag,owner_id:c.owner_id,owner_username:c.owner_username,stats:{wealth:c.wealth,military:c.military,tech:c.tech,happiness:c.happiness,stability:c.stability}}));
 const adminOn=!!me&&me.role==='admin';
 const actions=db.prepare(`SELECT a.*,u.username,c.name country_name FROM actions a JOIN users u ON u.id=a.player_id JOIN countries c ON c.id=a.country_id ${adminOn?'':'WHERE a.player_id=?'} ORDER BY a.id DESC LIMIT 100`).all(...(adminOn?[]:[me?.id||-1]));
 const news=db.prepare('SELECT id,text,created_at FROM news ORDER BY id DESC LIMIT 50').all();
 const users=adminOn?db.prepare('SELECT id,username,role,created_at FROM users ORDER BY id DESC').all():[];
 return {me:me?userPublic(me):null,admin:adminOn,countries:allCountries,actions,news,users};
}
app.get('/api/state',(req,res)=>res.json(stateFor(req)));
app.post('/api/register',async(req,res)=>{
 const username=String(req.body.username||'').trim(),password=String(req.body.password||'');
 if(!/^[\p{L}\p{N}_-]{3,24}$/u.test(username))return res.status(400).json({error:'نام کاربری باید ۳ تا ۲۴ نویسه و بدون فاصله باشد.'});
 if(password.length<8||password.length>128)return res.status(400).json({error:'رمز عبور باید حداقل ۸ نویسه باشد.'});
 if(db.prepare('SELECT id FROM users WHERE username=?').get(username))return res.status(409).json({error:'این نام کاربری قبلاً ثبت شده است.'});
 const hash=await bcrypt.hash(password,12);
 const result=db.prepare("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?, 'player', ?)").run(username,hash,now());
 req.session.userId=result.lastInsertRowid;res.json({ok:true});
});
app.post('/api/login',async(req,res)=>{
 const username=String(req.body.username||'').trim(),password=String(req.body.password||'');
 const u=db.prepare('SELECT * FROM users WHERE username=?').get(username);
 if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'نام کاربری یا رمز عبور اشتباه است.'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'خطای نشست'});req.session.userId=u.id;res.json({ok:true})});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('imperator.sid');res.json({ok:true})}));
app.post('/api/countries/:id/claim',requireAuth,(req,res)=>{
 const c=db.prepare('SELECT id,owner_id FROM countries WHERE id=?').get(req.params.id);
 if(!c)return res.status(404).json({error:'کشور پیدا نشد.'});
 if(c.owner_id)return res.status(409).json({error:'این کشور قبلاً انتخاب شده است.'});
 if(db.prepare('SELECT id FROM countries WHERE owner_id=?').get(req.session.userId))return res.status(409).json({error:'هر بازیکن فقط می‌تواند یک کشور داشته باشد.'});
 db.prepare('UPDATE countries SET owner_id=? WHERE id=? AND owner_id IS NULL').run(req.session.userId,c.id);res.json({ok:true});
});
app.post('/api/actions',requireAuth,(req,res)=>{
 const text=String(req.body.text||'').trim();if(!validText(text))return res.status(400).json({error:'متن اقدام الزامی است و حداکثر ۳۰۰۰ نویسه باشد.'});
 const c=db.prepare('SELECT id FROM countries WHERE owner_id=?').get(req.session.userId);if(!c)return res.status(400).json({error:'ابتدا یک کشور انتخاب کن.'});
 if(db.prepare("SELECT id FROM actions WHERE player_id=? AND status='pending'").get(req.session.userId))return res.status(409).json({error:'یک اقدام در انتظار پاسخ داری.'});
 db.prepare("INSERT INTO actions(player_id,country_id,text,status,created_at) VALUES(?,?,?,'pending',?)").run(req.session.userId,c.id,text,now());res.json({ok:true});
});
app.post('/api/actions/:id/answer',requireAdmin,(req,res)=>{
 const result=String(req.body.result||'').trim();if(!validText(result))return res.status(400).json({error:'نتیجه را وارد کن.'});
 const a=db.prepare("SELECT id FROM actions WHERE id=? AND status='pending'").get(Number(req.params.id));if(!a)return res.status(404).json({error:'اقدام در انتظار پیدا نشد.'});
 db.prepare("UPDATE actions SET result=?,status='answered',answered_at=? WHERE id=?").run(result,now(),a.id);res.json({ok:true});
});
app.post('/api/news',requireAdmin,(req,res)=>{
 const text=String(req.body.text||'').trim();if(!validText(text))return res.status(400).json({error:'متن خبر را وارد کن.'});
 db.prepare('INSERT INTO news(text,created_at,author_id) VALUES(?,?,?)').run(text,now(),req.session.userId);res.json({ok:true});
});
app.post('/api/admin/countries/:id/release',requireAdmin,(req,res)=>{
 const r=db.prepare('UPDATE countries SET owner_id=NULL WHERE id=?').run(req.params.id);if(!r.changes)return res.status(404).json({error:'کشور پیدا نشد.'});res.json({ok:true});
});
app.post('/api/admin/users/:id/release',requireAdmin,(req,res)=>{
 db.prepare('UPDATE countries SET owner_id=NULL WHERE owner_id=?').run(Number(req.params.id));res.json({ok:true});
});
app.patch('/api/admin/countries/:id/stats',requireAdmin,(req,res)=>{
 const keys=['wealth','military','tech','happiness','stability'],s=req.body.stats||{};
 if(keys.some(k=>!Number.isInteger(s[k])||s[k]<0||s[k]>100))return res.status(400).json({error:'همه آمار باید عدد صحیح بین ۰ تا ۱۰۰ باشند.'});
 const c=db.prepare('UPDATE countries SET wealth=?,military=?,tech=?,happiness=?,stability=? WHERE id=?').run(s.wealth,s.military,s.tech,s.happiness,s.stability,req.params.id);
 if(!c.changes)return res.status(404).json({error:'کشور پیدا نشد.'});res.json({ok:true});
});
app.delete('/api/admin/users/:id',requireAdmin,(req,res)=>{
 const id=Number(req.params.id);if(id===req.session.userId)return res.status(400).json({error:'نمی‌توانی حساب مدیر فعلی را حذف کنی.'});
 const u=db.prepare('SELECT role FROM users WHERE id=?').get(id);if(!u)return res.status(404).json({error:'کاربر پیدا نشد.'});
 if(u.role==='admin')return res.status(403).json({error:'حذف مدیر از این پنل مجاز نیست.'});
 db.prepare('DELETE FROM users WHERE id=?').run(id);res.json({ok:true});
});
app.delete('/api/admin/actions/:id',requireAdmin,(req,res)=>{
 const r=db.prepare('DELETE FROM actions WHERE id=?').run(Number(req.params.id));if(!r.changes)return res.status(404).json({error:'اقدام پیدا نشد.'});res.json({ok:true});
});
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,'0.0.0.0',()=>console.log(`Imperator running on port ${PORT}`));
