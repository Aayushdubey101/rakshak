"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { login, register, ApiError } from "@/lib/api";

interface AuthDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  defaultTab?: "login" | "register";
}

export function AuthDialog({ open, onOpenChange, defaultTab = "login" }: AuthDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Welcome to Rakshak</DialogTitle>
        </DialogHeader>
        <Tabs defaultValue={defaultTab}>
          <TabsList className="w-full">
            <TabsTrigger value="login" className="flex-1">Log in</TabsTrigger>
            <TabsTrigger value="register" className="flex-1">Create account</TabsTrigger>
          </TabsList>
          <TabsContent value="login">
            <LoginForm onSuccess={() => onOpenChange(false)} />
          </TabsContent>
          <TabsContent value="register">
            <RegisterForm onSuccess={() => onOpenChange(false)} />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}

function LoginForm({ onSuccess }: { onSuccess: () => void }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      onSuccess();
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not log in");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="pt-2">
      <div className="mb-3 grid gap-1.5">
        <Label htmlFor="login-email">Email</Label>
        <Input id="login-email" type="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </div>
      <div className="mb-4 grid gap-1.5">
        <Label htmlFor="login-password">Password</Label>
        <Input id="login-password" type="password" placeholder="••••••••" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </div>
      {error && <p className="mb-3 text-[13px] text-destructive">{error}</p>}
      <Button type="submit" disabled={submitting} className="w-full justify-center">
        {submitting ? "Logging in…" : "Sign in"}
      </Button>
      <div className="mt-3 text-[13px]">
        <Link href="/forgot-password" className="hover:text-primary">Forgot password?</Link>
      </div>
    </form>
  );
}

function RegisterForm({ onSuccess }: { onSuccess: () => void }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords don't match");
      return;
    }
    setSubmitting(true);
    try {
      await register(email, password);
      onSuccess();
      router.push("/onboarding");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create account");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="pt-2">
      <div className="mb-3 grid gap-1.5">
        <Label htmlFor="register-email">Email</Label>
        <Input id="register-email" type="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </div>
      <div className="mb-3 grid gap-1.5">
        <Label htmlFor="register-password">Password</Label>
        <Input id="register-password" type="password" placeholder="••••••••" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
      </div>
      <div className="mb-4 grid gap-1.5">
        <Label htmlFor="register-confirm">Confirm password</Label>
        <Input id="register-confirm" type="password" placeholder="••••••••" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
      </div>
      {error && <p className="mb-3 text-[13px] text-destructive">{error}</p>}
      <Button type="submit" disabled={submitting} className="w-full justify-center">
        {submitting ? "Creating…" : "Create account"}
      </Button>
    </form>
  );
}
