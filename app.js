// Shared code for every page. Load order: supabase-js, config.js, app.js
const sb = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

const ROLE_NAMES = { owner: '老板 Owner', manager: '经理 Manager', staff: '业务员 Staff' };

// Current user + profile, or null when not logged in
async function getMe() {
  const { data: { session } } = await sb.auth.getSession();
  if (!session) return null;
  const { data: profile } = await sb
    .from('profiles')
    .select('id, email, full_name, role, active')
    .eq('id', session.user.id)
    .maybeSingle();
  return { user: session.user, profile };
}

// Put at the top of every page: sends people who aren't allowed back to index.html
async function requireRole(allowedRoles) {
  const me = await getMe();
  const p = me && me.profile;
  if (!p || !p.active || !allowedRoles.includes(p.role)) {
    location.href = 'index.html';
    return null;
  }
  return me;
}

async function signOut() {
  await sb.auth.signOut();
  location.href = 'index.html';
}

// RM 1,234.50
function money(n) {
  return 'RM ' + Number(n || 0).toLocaleString('en-MY', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// '2026-11-17' or a timestamp -> 17 Nov 2026
function niceDate(value) {
  if (!value) return '';
  const d = /^\d{4}-\d{2}-\d{2}$/.test(value) ? new Date(value + 'T00:00:00') : new Date(value);
  if (isNaN(d)) return '';
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

function escapeHtml(text) {
  return String(text ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Turn technical errors into friendly words
function friendlyError(err) {
  const msg = (err && (err.message || err.error_description)) || String(err || '');
  if (/invalid login credentials/i.test(msg)) return 'Email 或密码不对，请再试一次。';
  if (/email not confirmed/i.test(msg)) return '请先去 email 点确认链接，然后再登录。';
  if (/already registered|already exists/i.test(msg)) return '这个 email 已经注册过了，请直接登录。';
  if (/password should be at least/i.test(msg)) return '密码最少要 6 个字。';
  if (/valid email|invalid email|unable to validate email/i.test(msg)) return 'Email 格式不对，请检查。';
  if (/rate limit|too many/i.test(msg)) return '试太多次了，请等几分钟再试。';
  if (/failed to fetch|network/i.test(msg)) return '连不上网络，请检查网络后再试。';
  if (/row-level security|permission denied/i.test(msg)) return '你没有权限做这件事。';
  return '出了点问题，请再试一次。（' + msg + '）';
}

function showMessage(el, text, kind) {
  el.textContent = text;
  el.className = 'msg ' + (kind || '');
  el.hidden = !text;
}
