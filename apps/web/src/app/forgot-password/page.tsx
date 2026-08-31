"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { forgotPassword, resetPassword, ApiError } from "@/lib/api";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // Dev-mode only (no email service configured yet): the backend returns the
  // reset token directly outside production so this flow is fully testable
  // locally. `apps/api/routers/auth.py::forgot_password` guards this on
  // `ENVIRONMENT != "production"`.
  const [devToken, setDevToken] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [done, setDone] = useState(false);

  async function onRequestReset(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await forgotPassword(email);
      setDevToken(result.dev_reset_token ?? null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not request a reset");
    } finally {
      setSubmitting(false);
    }
  }

  async function onResetPassword(e: FormEvent) {
    e.preventDefault();
    if (!devToken) return;
    setError(null);
    setSubmitting(true);
    try {
      await resetPassword(devToken, newPassword);
      setDone(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reset password");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div data-screen-label="forgot-password" className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-[380px]">
        <h3>Reset password</h3>

        {done ? (
          <>
            <p className="text-[13px] text-muted-rk">Password updated. You can log in now.</p>
            <Link href="/login" className="hover:text-primary">← Back to log in</Link>
          </>
        ) : devToken ? (
          <form onSubmit={onResetPassword}>
            <p className="text-[13px] text-muted-rk">Dev mode: no email service configured, so here's your reset token directly.</p>
            <p className="mb-3 break-all bg-muted p-2 font-mono text-[11px]">{devToken}</p>
            <div className="mb-4 grid gap-1.5">
              <Label htmlFor="new-password">New password</Label>
              <Input id="new-password" type="password" placeholder="••••••••" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={8} />
            </div>
            {error && <p className="mb-3 text-[13px] text-destructive">{error}</p>}
            <Button type="submit" disabled={submitting} className="w-full justify-center">
              {submitting ? "Resetting…" : "Set new password"}
            </Button>
          </form>
        ) : (
          <form onSubmit={onRequestReset}>
            <p className="text-[13px] text-muted-rk">Enter your account email and we&apos;ll send reset instructions.</p>
            <div className="mb-4 grid gap-1.5">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </div>
            {error && <p className="mb-3 text-[13px] text-destructive">{error}</p>}
            <Button type="submit" disabled={submitting} className="w-full justify-center">
              {submitting ? "Sending…" : "Send reset link"}
            </Button>
            <div className="mt-3 text-[13px]">
              <Link href="/login" className="hover:text-primary">← Back to log in</Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
