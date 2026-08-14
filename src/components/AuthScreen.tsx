import { useState } from "react";
import { useAuth } from "../lib/auth";
import { ShieldCheck, Sparkles, Radar, LockKeyhole } from "lucide-react";

export function AuthScreen() {
  const { signIn, signUp } = useAuth();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setBusy(true);
    if (mode === "signin") {
      const { error } = await signIn(email, password);
      if (error) setError(error);
    } else {
      const { error, needsConfirmation } = await signUp(email, password);
      if (error) setError(error);
      else if (needsConfirmation) setSuccess("Check your email for a confirmation link to finish creating your account.");
      else setSuccess("Account created. Your workspace is being prepared.");
    }
    setBusy(false);
  };

  return (
    <div className="auth-screen">
      <div className="auth-orbit auth-orbit-one" />
      <div className="auth-orbit auth-orbit-two" />
      <div className="auth-layout">
      <div className="auth-card slide-up">
        <div className="auth-brand">
          <div className="auth-brand-text">
            <h1>CASPER DEE</h1>
            <p>Security Decision Engine</p>
          </div>
        </div>

        <div className="auth-tagline">Know what matters.<br />Fix what matters first.</div>

        <div className="auth-eyebrow"><span className="pulse-dot" /> LIVE DEFENSE INTELLIGENCE</div>

        <h2 className="auth-heading">{mode === "signin" ? "Welcome back" : "Create your account"}</h2>
        <p className="auth-subheading">
          {mode === "signin"
            ? "Sign in to your security workspace."
            : "Spin up a workspace preloaded with your security posture."}
        </p>

        {error && <div className="auth-error">{error}</div>}
        {success && <div className="auth-success">{success}</div>}

        <form onSubmit={submit}>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              className="form-input"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              autoComplete="email"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              className="form-input"
              type="password"
              required
              minLength={6}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 6 characters"
              autoComplete={mode === "signin" ? "current-password" : "new-password"}
            />
          </div>
          <button type="submit" className="btn btn-primary w-full" disabled={busy} style={{ justifyContent: "center", marginTop: 8 }}>
            {busy ? <span className="spinner" /> : mode === "signin" ? "Sign in" : "Create account"}
          </button>
        </form>

        <div className="auth-toggle">
          {mode === "signin" ? (
            <>Don't have an account? <button onClick={() => { setMode("signup"); setError(null); }}>Sign up</button></>
          ) : (
            <>Already have an account? <button onClick={() => { setMode("signin"); setError(null); }}>Sign in</button></>
          )}
        </div>

        <div className="auth-principles">
          <div><Radar size={14} /><span>Evidence, not guesses</span></div>
          <div><LockKeyhole size={14} /><span>Authorized by design</span></div>
          <div><ShieldCheck size={14} /><span>Built for defenders</span></div>
        </div>

        <div className="auth-powered">
          <Sparkles size={12} /> Powered by <strong>Wiltecon Technologies</strong>
        </div>
      </div>
      <div className="auth-guide-wrap">
        <div className="auth-guide-card" aria-hidden="true">
          <div className="auth-guide-header">
            <span className="auth-guide-badge">CASPER DEE</span>
            <span className="auth-guide-status"><span className="pulse-dot" /> LIVE</span>
          </div>
          <div className="auth-guide-grid">
            <div className="auth-guide-panel">
              <span className="auth-guide-label">Threat posture</span>
              <strong>Risk-aware</strong>
            </div>
            <div className="auth-guide-panel">
              <span className="auth-guide-label">Coverage</span>
              <strong>Authorized targets</strong>
            </div>
            <div className="auth-guide-panel wide">
              <span className="auth-guide-label">Active signal</span>
              <div className="auth-guide-bars" aria-hidden="true">
                <span />
                <span />
                <span />
                <span />
                <span />
              </div>
            </div>
          </div>
        </div>
        <p className="auth-guide-caption">CASPER DEE V1 · trusted security operations</p>
      </div>
      </div>
    </div>
  );
}
