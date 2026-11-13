import crypto from "node:crypto";
import AdmZip from "adm-zip";
import type { Express, Request, Response } from "express";
import multer from "multer";

const MAX_UPLOAD = 100 * 1024 * 1024;
const MAX_FILES = 3000;
const MAX_TOTAL_EXTRACTED = 250 * 1024 * 1024;
const sessions = new Map<string, { token: string; user: GithubUser; expiresAt: number }>();
const states = new Map<string, number>();

type GithubUser = { login: string; name: string | null; avatar_url: string; html_url: string };

type RepoFile = { path: string; mode: "100644"; type: "blob"; content: string };

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD, files: 1 },
});

function cookieOptions(maxAge: number) {
  return `Path=/; Max-Age=${Math.floor(maxAge / 1000)}; HttpOnly; SameSite=None; Secure`;
}

function setCookie(res: Response, name: string, value: string, maxAge: number) {
  res.setHeader("Set-Cookie", `${name}=${encodeURIComponent(value)}; ${cookieOptions(maxAge)}`);
}

function getCookie(req: Request, name: string) {
  return (req.headers.cookie ?? "").split(";").map(v => v.trim()).find(v => v.startsWith(`${name}=`))?.slice(name.length + 1);
}

function callbackUrl(req: Request) {
  const proto = String(req.headers["x-forwarded-proto"] ?? "https").split(",")[0];
  const host = req.headers["x-forwarded-host"] ?? req.headers.host;
  return `${proto}://${host}/api/github/callback`;
}

async function github(path: string, init: RequestInit = {}, token?: string) {
  const response = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "RepoForge",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(init.headers ?? {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data?.message === "string" ? data.message : `GitHub error ${response.status}`);
  return data;
}

function currentSession(req: Request) {
  const id = getCookie(req, "repoforge_session");
  const session = id ? sessions.get(id) : undefined;
  if (!session || session.expiresAt < Date.now()) {
    if (id) sessions.delete(id);
    return undefined;
  }
  return session;
}

function safePath(path: string) {
  const normalized = path.replaceAll("\\", "/");
  return normalized && !normalized.startsWith("/") && !normalized.split("/").some(part => part === ".." || part === "." || part === "") ? normalized : null;
}

function isArchive(file: Express.Multer.File) {
  return /\.(zip|apk)$/i.test(file.originalname) || file.buffer.subarray(0, 4).toString("hex") === "504b0304";
}

function extract(file: Express.Multer.File) {
  if (!isArchive(file)) {
    const filename = safePath(file.originalname.split(/[\\/]/).pop() || "uploaded-file") || "uploaded-file";
    return { files: [{ path: filename, mode: "100644" as const, type: "blob" as const, content: file.buffer.toString("base64") }], total: file.size, archived: false };
  }
  const zip = new AdmZip(file.buffer);
  const entries = zip.getEntries();
  if (entries.length === 0) throw new Error("الملف فارغ");
  if (entries.length > MAX_FILES) throw new Error(`الملف يحتوي على ملفات كثيرة جداً (الحد ${MAX_FILES})`);
  const files: RepoFile[] = [];
  let total = 0;
  for (const entry of entries) {
    if (entry.isDirectory) continue;
    const path = safePath(entry.entryName);
    if (!path) throw new Error("الملف يحتوي على مسار غير آمن");
    const data = entry.getData();
    total += data.byteLength;
    if (total > MAX_TOTAL_EXTRACTED) throw new Error("الحجم بعد الفك كبير جداً");
    files.push({ path, mode: "100644", type: "blob", content: data.toString("base64") });
  }
  if (!files.length) throw new Error("لم نجد ملفات قابلة للنشر");
  return { files, total, archived: true };
}

function requireSession(req: Request, res: Response) {
  const session = currentSession(req);
  if (!session) res.status(401).json({ error: "سجل الدخول إلى GitHub أولاً" });
  return session;
}

export function registerGithubRoutes(app: Express) {
  app.get("/api/github/login", (req, res) => {
    const clientId = process.env.GITHUB_CLIENT_ID;
    if (!clientId) return res.status(503).send("لم يتم إعداد GITHUB_CLIENT_ID على الخادم بعد");
    const state = crypto.randomBytes(24).toString("hex");
    states.set(state, Date.now() + 10 * 60_000);
    setCookie(res, "repoforge_oauth_state", state, 10 * 60_000);
    const params = new URLSearchParams({ client_id: clientId, redirect_uri: callbackUrl(req), scope: "repo", state });
    res.redirect(`https://github.com/login/oauth/authorize?${params}`);
  });

  app.get("/api/github/callback", async (req, res) => {
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const cookieState = getCookie(req, "repoforge_oauth_state");
    const expires = states.get(state);
    states.delete(state);
    if (!code || !state || state !== cookieState || !expires || expires < Date.now()) return res.status(403).send("جلسة تسجيل الدخول غير صالحة، أعد المحاولة");
    try {
      const token = await githubToken(code, callbackUrl(req));
      const user = await github("/user", {}, token) as GithubUser;
      const sessionId = crypto.randomBytes(32).toString("hex");
      sessions.set(sessionId, { token, user, expiresAt: Date.now() + 60 * 60_000 });
      setCookie(res, "repoforge_session", sessionId, 60 * 60_000);
      res.redirect("/");
    } catch (error) {
      console.error("[GitHub OAuth]", error);
      res.status(502).send("تعذر إكمال تسجيل الدخول إلى GitHub");
    }
  });

  app.get("/api/github/me", (req, res) => {
    const session = currentSession(req);
    res.json({ user: session?.user ?? null });
  });

  app.post("/api/github/logout", (req, res) => {
    const id = getCookie(req, "repoforge_session");
    if (id) sessions.delete(id);
    setCookie(res, "repoforge_session", "", 0);
    res.json({ ok: true });
  });

  app.post("/api/forge/inspect", upload.single("file"), (req, res) => {
    if (!requireSession(req, res)) return;
    try {
      if (!req.file) return res.status(400).json({ error: "اختر ملفاً أولاً" });
      const result = extract(req.file);
      res.json({ fileName: req.file.originalname, fileSize: req.file.size, fileCount: result.files.length, totalSize: result.total, archived: result.archived, preview: result.files.slice(0, 12).map(file => file.path), hasIndex: result.files.some(file => file.path.toLowerCase().endsWith("index.html")) });
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : "تعذر فك الملف" });
    }
  });

  app.post("/api/forge/publish", upload.single("file"), async (req, res) => {
    const session = requireSession(req, res);
    if (!session) return;
    try {
      if (!req.file) return res.status(400).json({ error: "اختر ملفاً أولاً" });
      const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
      const description = typeof req.body.description === "string" ? req.body.description : "";
      const isPrivate = req.body.private === "true";
      const wantsPages = req.body.publishPages === "true";
      if (!name) return res.status(400).json({ error: "اكتب اسم المستودع" });
      if (!/^[A-Za-z0-9_.-]+$/.test(name) || name.length > 100) return res.status(400).json({ error: "اسم المستودع يقبل الإنجليزية والأرقام و . _ - فقط" });
      const { files } = extract(req.file);
      let repo = await createGithubRepo(session.user.login, name, description, isPrivate, session.token);
      const branch = repo.default_branch || "main";
      const recoveredEmptyRepo = Boolean(repo.__repoforgeInitialized);
      if (recoveredEmptyRepo) {
        await github(`/repos/${session.user.login}/${repo.name}/contents/.repoforge-init`, { method: "PUT", body: JSON.stringify({ message: "Initialize via RepoForge", content: Buffer.from("RepoForge initialization marker\n").toString("base64"), branch }) }, session.token);
        repo = await github(`/repos/${session.user.login}/${repo.name}`, {}, session.token);
      }
      const branchRef = await github(`/repos/${session.user.login}/${repo.name}/git/ref/heads/${branch}`, {}, session.token);
      const baseCommitSha = branchRef.object.sha as string;
      const baseCommit = await github(`/repos/${session.user.login}/${repo.name}/git/commits/${baseCommitSha}`, {}, session.token);
      const blobs = [];
      for (const file of files) {
        const blob = await github(`/repos/${session.user.login}/${repo.name}/git/blobs`, { method: "POST", body: JSON.stringify({ content: file.content, encoding: "base64" }) }, session.token);
        blobs.push({ path: file.path, mode: file.mode, type: file.type, sha: blob.sha });
      }
      const treeEntries = recoveredEmptyRepo
        ? [...blobs, { path: ".repoforge-init", mode: "100644", type: "blob", sha: null }]
        : blobs;
      const tree = await github(`/repos/${session.user.login}/${repo.name}/git/trees`, { method: "POST", body: JSON.stringify({ base_tree: baseCommit.tree.sha, tree: treeEntries }) }, session.token);
      const commit = await github(`/repos/${session.user.login}/${repo.name}/git/commits`, { method: "POST", body: JSON.stringify({ message: "Import via RepoForge", tree: tree.sha, parents: [baseCommitSha] }) }, session.token);
      await github(`/repos/${session.user.login}/${repo.name}/git/refs/heads/${branch}`, { method: "PATCH", body: JSON.stringify({ sha: commit.sha, force: false }) }, session.token);
      let pagesUrl: string | null = null;
      let pagesWarning: string | null = null;
      if (wantsPages && files.some(file => file.path.toLowerCase().endsWith("index.html"))) {
        try {
          await github(`/repos/${session.user.login}/${repo.name}/pages`, { method: "POST", body: JSON.stringify({ source: { branch, path: "/" } }) }, session.token);
          pagesUrl = `https://${session.user.login}.github.io/${repo.name}/`;
        } catch (pagesError) {
          pagesWarning = isPrivate ? "تم إنشاء المستودع الخاص، لكن GitHub Pages قد يتطلب خطة مدفوعة." : (pagesError instanceof Error ? pagesError.message : "تعذر تفعيل GitHub Pages");
        }
      } else if (wantsPages) {
        pagesWarning = "لم نجد index.html، لذلك لم يتم تفعيل GitHub Pages.";
      }
      res.json({ url: repo.html_url, name: repo.name, pagesUrl, pagesWarning });
    } catch (error) {
      console.error("[RepoForge publish]", error);
      res.status(400).json({ error: error instanceof Error ? error.message : "تعذر النشر إلى GitHub" });
    }
  });
}

async function createGithubRepo(login: string, name: string, description: string, isPrivate: boolean, token: string) {
  try {
    return await github("/user/repos", { method: "POST", body: JSON.stringify({ name, description, private: isPrivate, auto_init: true }) }, token);
  } catch (createError) {
    try {
      const existing = await github(`/repos/${login}/${name}`, {}, token);
      if (existing.owner?.login !== login || existing.size > 0 || existing.fork) {
        throw createError;
      }
      return { ...existing, __repoforgeInitialized: true };
    } catch {
      throw createError;
    }
  }
}

async function githubToken(code: string, redirectUri: string) {
  const response = await fetch("https://github.com/login/oauth/access_token", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code, redirect_uri: redirectUri }) });
  const data = await response.json() as { access_token?: string; error?: string };
  if (!response.ok || !data.access_token) throw new Error(data.error ?? "لم يتم الحصول على token");
  return data.access_token;
}
