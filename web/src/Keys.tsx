// Setup → Recording → Decryption keys (desktop app): the KFDtool key container and the file
// holding its password (docs/configuration/encryption.md), and, when only the container is set,
// the password to open it with, typed here. The password goes to the recorder once, from the
// recorder's own computer only; it is not stored, not shown again, and never sent back. The
// keys are never sent to any browser: only which are held, by algorithm, key id and name.

import { useState } from "react";
import { askKeys, lockKeys, reloadKeys, unlockKeys, updateConfig, useApp } from "./controller.ts";
import { cipherName } from "./dash/Calls.tsx";

/** Whether this page was opened on the computer the recorder runs on (the only place keys can be unlocked). */
const onThisComputer = () => ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname) || location.hostname.endsWith(".localhost");

const STATE_TEXT = {
  off: "No key container set.",
  locked: "Locked: enter the container's password.",
  unlocked: "Unlocked.",
  error: "The keys didn't load.",
} as const;

export function KeysPanel() {
  const { config: c, keys, heldKeys, heldKeysRestricted } = useApp();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  if (!c) return null;
  const k = c.keys ?? { ekcFile: "", passwordFile: "" };
  const edit = (patch: Partial<typeof k>) => updateConfig((x) => void (x.keys = { ...(x.keys ?? { ekcFile: "", passwordFile: "" }), ...patch }));
  const state = keys?.state ?? "off";
  const local = onThisComputer() || !!k.allowLanUnlock;
  const canType = state === "locked" || (state === "unlocked" && keys?.source === "password");

  const act = async (f: () => Promise<{ ok: boolean; message: string | null }>, done: string) => {
    setBusy(true);
    setResult(null);
    const r = await f();
    setBusy(false);
    setPassword("");
    // (A success shows in the state above; only a failure needs saying.)
    setResult(r.ok ? null : { ok: false, text: r.message ?? done });
  };

  return (
    <section className="panel" aria-labelledby="keys-title">
      <header className="panel-head">
        <h2 id="keys-title">Decryption keys</h2>
        <span className={`badge ${state === "error" ? "bad" : ""}`} style={state === "unlocked" ? { background: "var(--ok)", color: "#fff" } : undefined}>
          {state === "unlocked" ? `${keys?.count ?? 0} KEYS` : state === "locked" ? "LOCKED" : state === "error" ? "ERROR" : "OFF"}
        </span>
      </header>
      <div className="stack">
        <p className="muted small">
          Decrypts P25 calls whose key is in a KFDtool key container (<code>.ekc</code>). Calls under other keys are left as they were.{" "}
          <a href="https://github.com/connorjfarrell/trunk-recorder-pro/blob/main/docs/configuration/encryption.md" target="_blank" rel="noreferrer">
            Details
          </a>
        </p>
        <div className="row wrap" style={{ alignItems: "flex-start", gap: 8 }}>
          <div className="field" style={{ flex: 1, minWidth: "16em" }}>
            <label className="field-label" htmlFor="keys-ekc">
              Key container (.ekc)
            </label>
            <input id="keys-ekc" className="mono" value={k.ekcFile} placeholder="/etc/trunk-pro/keys.ekc" onChange={(e) => edit({ ekcFile: e.target.value })} />
          </div>
          <div className="field" style={{ flex: 1, minWidth: "16em" }}>
            <label className="field-label" htmlFor="keys-pw">
              Password file (optional)
            </label>
            <input id="keys-pw" className="mono" value={k.passwordFile} placeholder="/etc/trunk-pro/keys.pw" onChange={(e) => edit({ passwordFile: e.target.value })} />
            <span className="field-hint">
              Readable by you alone (<code>chmod 600</code>). Leave it empty to type the password here instead.
            </span>
          </div>
        </div>

        <p className={state === "error" ? "bad-text" : "muted"} role="status">
          {STATE_TEXT[state]}
          {keys?.source === "file" && " (from the password file)"}
          {keys?.source === "password" && " (with the password you typed; kept in memory until you lock it or quit; locking applies to calls that start afterwards)"}
          {keys?.message && <> {keys.message}</>}
        </p>

        {canType && (
          <form
            className="row wrap"
            style={{ gap: 8, alignItems: "flex-end" }}
            onSubmit={(e) => {
              e.preventDefault();
              if (password && !busy) void act(() => unlockKeys(password), "Failed.");
            }}
          >
            {state === "locked" && (
              <div className="field">
                <label className="field-label" htmlFor="keys-password">
                  Container password
                </label>
                <input
                  id="keys-password"
                  type="password"
                  autoComplete="off"
                  name="keys-container-password"
                  value={password}
                  disabled={!local || busy}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            )}
            {state === "locked" && (
              <button className="btn" type="submit" disabled={!local || busy || !password}>
                Unlock
              </button>
            )}
            {state === "unlocked" && (
              <button className="btn" type="button" disabled={!local || busy} onClick={() => void act(lockKeys, "Failed.")}>
                Lock
              </button>
            )}
          </form>
        )}
        {state === "locked" && !local && (
          <p className="muted small">
            Keys can only be unlocked from the computer the recorder runs on: open this page at <code>http://localhost</code> there (over SSH,
            forward the port), or set a password file.
          </p>
        )}
        {state === "error" && (
          <div className="row">
            <button className="btn small" disabled={busy || !local} onClick={() => void act(reloadKeys, "Failed.")}>
              Try again
            </button>
          </div>
        )}
        {result && (
          <p className={result.ok ? "muted" : "bad-text"} role="alert">
            {result.text}
          </p>
        )}

        {state === "unlocked" && (
          <div>
            {heldKeysRestricted ? (
              <p className="muted small">Which keys are held is shown on the recorder's own computer only.</p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Cipher</th>
                    <th>Key ID</th>
                  </tr>
                </thead>
                <tbody>
                  {heldKeys.map((h) => (
                    <tr key={`${h.algId}-${h.keyId}`}>
                      <td>{h.name || "—"}</td>
                      <td>{cipherName(h.algId)}</td>
                      <td className="mono">{h.keyId}</td>
                    </tr>
                  ))}
                  {heldKeys.length === 0 && (
                    <tr>
                      <td colSpan={3} className="muted">
                        <button className="linkish" onClick={askKeys}>
                          Show the keys held
                        </button>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
