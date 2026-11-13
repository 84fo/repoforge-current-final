import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, Check, ChevronLeft, FileArchive, Github, Loader2, LogOut, ShieldCheck, Sparkles, UploadCloud, X } from "lucide-react";

type User = { login: string; name: string | null; avatar_url: string; html_url: string };
type Inspect = { fileName: string; fileSize: number; fileCount: number; totalSize: number; preview: string[]; archived: boolean; hasIndex?: boolean };

type Phase = "idle" | "inspecting" | "ready" | "publishing" | "success" | "error";

const formatBytes = (value: number) => value < 1024 * 1024 ? `${Math.max(1, Math.round(value / 1024))} KB` : `${(value / 1024 / 1024).toFixed(1)} MB`;

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [inspect, setInspect] = useState<Inspect | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("مستورد عبر RepoForge");
  const [visibility, setVisibility] = useState<"public" | "private">("public");
  const [publishPages, setPublishPages] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [pagesUrl, setPagesUrl] = useState("");
  const [pagesWarning, setPagesWarning] = useState("");
  const [dragging, setDragging] = useState(false);

  useEffect(() => { fetch("/api/github/me").then(r => r.json()).then(data => setUser(data.user)).catch(() => undefined); }, []);
  const isBusy = phase === "inspecting" || phase === "publishing";
  const progress = useMemo(() => [
    { label: "تسجيل الدخول", done: Boolean(user) },
    { label: "فحص الملف", done: Boolean(inspect) },
    { label: "النشر في GitHub", done: phase === "success" },
  ], [user, inspect, phase]);

  const pickFile = (next: File | null) => {
    setError(""); setRepoUrl(""); setInspect(null); setPhase("idle");
    if (!next) return;
    if (next.size > 100 * 1024 * 1024) return setError("الحد الأقصى لحجم الملف هو 100 MB");
    setFile(next);
  };

  const inspectFile = async () => {
    if (!file) return setError("اختر ملفاً أولاً");
    if (!user) return window.location.assign("/api/github/login");
    setPhase("inspecting"); setError("");
    const form = new FormData(); form.append("file", file);
    const response = await fetch("/api/forge/inspect", { method: "POST", body: form });
    const data = await response.json();
    if (!response.ok) { setPhase("error"); return setError(data.error ?? "تعذر فحص الملف"); }
    setInspect(data); setPhase("ready");
    if (!name) setName(file.name.replace(/\.(zip|apk)$/i, "").replace(/[^A-Za-z0-9_.-]/g, "-").slice(0, 80) || "my-repo");
  };

  const publish = async () => {
    if (!file || !inspect) return;
    setPhase("publishing"); setError("");
    const form = new FormData(); form.append("file", file); form.append("name", name); form.append("description", description); form.append("private", String(visibility === "private")); form.append("publishPages", String(publishPages));
    const response = await fetch("/api/forge/publish", { method: "POST", body: form });
    const data = await response.json();
    if (!response.ok) { setPhase("error"); return setError(data.error ?? "تعذر النشر"); }
    setRepoUrl(data.url); setPagesUrl(data.pagesUrl ?? ""); setPagesWarning(data.pagesWarning ?? ""); setPhase("success");
  };

  const reset = () => { setFile(null); setInspect(null); setPhase("idle"); setError(""); setRepoUrl(""); setPagesUrl(""); setPagesWarning(""); };

  return <main className="app-shell" dir="rtl">
    <header className="topbar">
      <div className="brand"><span className="brand-mark">{`{·}`}</span><span>RepoForge</span></div>
      <div className="top-actions">
        <span className="credit-note"><Sparkles size={14} /> خفيف ومباشر</span>
        {user ? <button className="user-chip" onClick={() => { fetch("/api/github/logout", { method: "POST" }).then(() => setUser(null)); }}><img src={user.avatar_url} alt="" /><span>{user.login}</span><LogOut size={15} /></button> : <a className="github-link" href="/api/github/login"><Github size={17} /> تسجيل GitHub</a>}
      </div>
    </header>

    <section className="hero">
      <div className="hero-copy"><p className="eyebrow">FROM FILE TO REPOSITORY</p><h1>ملفك.<br /><em>مستودعك.</em></h1><p className="hero-lede">ارفع أي ملف، أو حزمة ZIP / APK، وانشره في GitHub. وحتى مواقعك نجهز لها رابطًا مباشرًا.</p><div className="trust-line"><ShieldCheck size={16} /> لا نخزن ملفاتك — المعالجة مؤقتة على الخادم</div></div>
      <div className="workspace">
        <div className="step-rail">{progress.map((item, index) => <div className={`rail-item ${item.done ? "done" : ""}`} key={item.label}><span>{item.done ? <Check size={13} /> : `0${index + 1}`}</span><small>{item.label}</small></div>)}</div>
        <div className="card-content">
          {!user && <div className="login-banner"><div><strong>ابدأ بتسجيل الدخول</strong><p>نحتاج صلاحية إنشاء مستودع ورفع الملفات إلى حسابك.</p></div><a href="/api/github/login" className="primary-button"><Github size={18} /> دخول GitHub <ArrowUpRight size={16} /></a></div>}
          <div className={`dropzone ${dragging ? "dragging" : ""} ${file ? "has-file" : ""}`} onDragOver={event => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); pickFile(event.dataTransfer.files[0] ?? null); }}>
            <input id="file-input" type="file" accept="*/*" hidden onChange={event => pickFile(event.target.files?.[0] ?? null)} />
            {file ? <><div className="file-icon"><FileArchive size={25} /></div><div className="file-details"><strong>{file.name}</strong><span>{formatBytes(file.size)} · جاهز للفحص</span></div><button className="icon-button" onClick={reset} aria-label="حذف الملف"><X size={18} /></button></> : <div className="drop-prompt"><span className="upload-icon"><UploadCloud size={26} /></span><strong>اسحب أي ملف هنا</strong><span>ZIP وAPK تُفك تلقائيًا · أي نوع ملف · حتى 100 MB</span><label htmlFor="file-input" className="primary-button file-picker-button">اختيار ملف من الجوال <UploadCloud size={16} /></label></div>}
          </div>
          {file && !inspect && <button className="primary-button full" disabled={isBusy} onClick={inspectFile}>{phase === "inspecting" ? <><Loader2 className="spin" size={18} /> نفحص المحتوى...</> : <>فك وفحص الملف <ChevronLeft size={18} /></>}</button>}
          {inspect && phase !== "success" && <div className="setup-panel"><div className="panel-heading"><div><p className="eyebrow">READY TO SHIP</p><h2>{inspect.archived ? "فُكّ الملف وجاهز." : "الملف جاهز."}</h2></div><span className="stat-pill"><Check size={14} /> {inspect.fileCount} ملف</span></div><div className="summary-row"><span>الحجم بعد المعالجة</span><b>{formatBytes(inspect.totalSize)}</b><span className="dot-separator">·</span><span>{inspect.archived ? "تم فك الحزمة" : "ملف مباشر"}</span></div><div className="file-list">{inspect.preview.map(path => <code key={path}>{path}</code>)}{inspect.fileCount > inspect.preview.length && <code>+ {inspect.fileCount - inspect.preview.length} ملفات أخرى</code>}</div><label className="field-label">اسم المستودع <span>قيود GitHub: أحرف إنجليزية، أرقام، . _ -</span><input value={name} onChange={event => setName(event.target.value)} placeholder="my-repository" dir="ltr" /></label><label className="field-label">الوصف <span>يدعم العربي، Unicode والإيموجي كما تريد</span><textarea value={description} onChange={event => setDescription(event.target.value)} placeholder="اكتب أي وصف هنا ✨" rows={3} /></label><div className="option-grid"><button type="button" className={`choice-card ${visibility === "public" ? "selected" : ""}`} onClick={() => setVisibility("public")}><span className="choice-icon">◉</span><span><b>عام</b><small>يظهر للجميع</small></span></button><button type="button" className={`choice-card ${visibility === "private" ? "selected" : ""}`} onClick={() => setVisibility("private")}><span className="choice-icon">⌑</span><span><b>خاص</b><small>لك وحدك</small></span></button></div><label className={`pages-toggle ${publishPages ? "selected" : ""}`}><input type="checkbox" checked={publishPages} onChange={event => setPublishPages(event.target.checked)} /><span><b>فعّل GitHub Pages</b><small>إذا وجدنا index.html سنعطيك رابط الموقع تلقائيًا</small></span><span className="toggle-pill">{publishPages ? "ON" : "OFF"}</span></label><button className="primary-button full" disabled={isBusy || !name} onClick={publish}>{phase === "publishing" ? <><Loader2 className="spin" size={18} /> ننشر الملفات...</> : <>إنشاء المستودع والنشر <ArrowUpRight size={18} /></>}</button></div>}
          {phase === "success" && <div className="success-panel"><div className="success-icon"><Check size={25} /></div><p className="eyebrow">PUBLISHED SUCCESSFULLY</p><h2>تم النشر بنجاح.</h2><p>ملفاتك الآن داخل مستودع GitHub {visibility === "private" ? "الخاص" : "العام"}.</p><div className="result-links"><a className="primary-button" href={repoUrl} target="_blank" rel="noreferrer">فتح المستودع <ArrowUpRight size={16} /></a>{pagesUrl && <a className="pages-link" href={pagesUrl} target="_blank" rel="noreferrer">فتح رابط الموقع <ArrowUpRight size={16} /></a>}</div>{pagesWarning && <div className="warning-message">{pagesWarning}</div>}<button className="text-button" onClick={reset}>رفع ملف آخر</button></div>}
          {error && <div className="error-message">{error}</div>}
        </div>
      </div>
    </section>
    <footer><span>RepoForge / 2026</span><span>يفك. يرتّب. ينشر.</span></footer>
  </main>;
}
