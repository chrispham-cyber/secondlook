"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, scanMessage, type ScanResult } from "@/lib/api";
import { Result } from "./Result";

type Mode = "screenshot" | "text";

const STEPS = ["Reading the message…", "Checking the links…", "Comparing with known scams…", "Writing up what we found…"];
const MAX_MB = 8;
const ACCEPT = "image/png,image/jpeg,image/webp,image/gif,image/heic,image/heif";

export function Checker() {
  const [mode, setMode] = useState<Mode>("screenshot");
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [note, setNote] = useState("");
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  const pick = useCallback((f: File | undefined | null) => {
    if (!f) return;
    if (!f.type.startsWith("image/") && !/\.(heic|heif)$/i.test(f.name)) {
      setError("That file isn't a picture. Take a screenshot of the message and upload that.");
      return;
    }
    if (f.size > MAX_MB * 1024 * 1024) {
      setError(`That picture is over ${MAX_MB} MB. Try a regular screenshot instead of a photo.`);
      return;
    }
    setError(null);
    setResult(null);
    setMode("screenshot");
    setFile(f);
    setPreview(URL.createObjectURL(f));
  }, []);

  // Free the old preview's memory whenever it is replaced or the page closes.
  useEffect(() => {
    return () => {
      if (preview) URL.revokeObjectURL(preview);
    };
  }, [preview]);

  function choose(f: File | null) {
    setFile(f);
    setPreview(f ? URL.createObjectURL(f) : null);
  }

  // Paste a screenshot from the clipboard anywhere on the page.
  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      const img = Array.from(e.clipboardData?.files ?? []).find((f) => f.type.startsWith("image/"));
      if (img) {
        e.preventDefault();
        pick(img);
      }
    };
    window.addEventListener("paste", onPaste);
    return () => window.removeEventListener("paste", onPaste);
  }, [pick]);

  useEffect(() => {
    if (!busy) return;
    const id = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 2600);
    return () => clearInterval(id);
  }, [busy]);

  const canSubmit = !busy && (mode === "screenshot" ? !!file : text.trim().length > 0);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setStep(0);
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r =
        mode === "screenshot" ? await scanMessage({ image: file, text: note }) : await scanMessage({ text });
      setResult(r);
      requestAnimationFrame(() => resultRef.current?.focus());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    choose(null);
    setText("");
    setNote("");
    setResult(null);
    setError(null);
  }

  return (
    <>
      <form className="checker" onSubmit={submit} aria-busy={busy}>
        <div className="mode-switch" role="group" aria-label="What do you want to check?">
          <button type="button" aria-pressed={mode === "screenshot"} onClick={() => setMode("screenshot")}>
            Screenshot
          </button>
          <button type="button" aria-pressed={mode === "text"} onClick={() => setMode("text")}>
            Paste text or a link
          </button>
        </div>

        {busy ? (
          <div className="working" role="status" aria-live="polite">
            <svg className="lens" viewBox="0 0 32 32" aria-hidden="true">
              <circle cx="13" cy="13" r="9" fill="none" stroke="currentColor" strokeWidth="2.6" />
              <path d="M20 20l8 8" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
            </svg>
            <p>{STEPS[step]}</p>
            <small>This usually takes 10 to 30 seconds, sometimes up to a minute.</small>
          </div>
        ) : mode === "screenshot" ? (
          <>
            {file && preview ? (
              <div className="preview">
                {/* eslint-disable-next-line @next/next/no-img-element -- local blob preview */}
                <img src={preview} alt="The screenshot you chose" />
                <div className="file-meta">
                  <p className="file-name">{file.name || "Pasted screenshot"}</p>
                  <button type="button" className="link-btn" onClick={() => choose(null)}>
                    Choose a different picture
                  </button>
                  <label className="field-label" htmlFor="note">
                    Anything we should know? <span className="hint">(optional)</span>
                  </label>
                  <textarea
                    id="note"
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="For example: “This came from a number I don’t know.”"
                    style={{ minHeight: "5rem" }}
                    maxLength={1000}
                  />
                </div>
              </div>
            ) : (
              <label
                className={`dropzone${dragging ? " is-dragging" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragging(false);
                  pick(e.dataTransfer.files[0]);
                }}
              >
                <input type="file" accept={ACCEPT} onChange={(e) => pick(e.target.files?.[0])} />
                <div>
                  <strong>Choose a screenshot</strong>
                  <span>
                    or drag it here, or press <kbd className="kbd">Ctrl</kbd> + <kbd className="kbd">V</kbd> to paste
                  </span>
                </div>
              </label>
            )}
          </>
        ) : (
          <>
            <label className="field-label" htmlFor="msg" style={{ marginTop: 0 }}>
              Paste the message, email, or link
            </label>
            <textarea
              id="msg"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="USPS: Your package is on hold. Confirm your address at usps-redelivery.info"
              maxLength={10000}
            />
          </>
        )}

        {!busy && (
          <div className="actions">
            <button type="submit" className="btn" disabled={!canSubmit}>
              Check this message
            </button>
            {(file || text || result) && (
              <button type="button" className="link-btn" onClick={reset}>
                Start over
              </button>
            )}
          </div>
        )}

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        <p className="privacy">
          We read your screenshot, then throw it away. It is never saved. Cover any account numbers before uploading if you
          like.
        </p>
      </form>

      <div ref={resultRef} tabIndex={-1} style={{ outline: "none" }}>
        {result && <Result result={result} />}
      </div>
    </>
  );
}
