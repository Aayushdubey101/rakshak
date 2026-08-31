"use client";

import { useRouter } from "next/navigation";
import { useState, type DragEvent } from "react";
import { FileText, ImageIcon, Link as LinkIcon, MessageSquare } from "lucide-react";
import { IntelligenceCore } from "@/components/intelligence-core";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { analyzeChecklist } from "@/lib/mock-data";
import { analyzeText, analyzeLink, analyzeUpload, ApiError } from "@/lib/api";

type AnalyzeType = "message" | "image" | "link" | "document";

const TABS: { type: AnalyzeType; label: string; icon: typeof MessageSquare }[] = [
  { type: "message", label: "Message", icon: MessageSquare },
  { type: "image", label: "Image", icon: ImageIcon },
  { type: "link", label: "Link", icon: LinkIcon },
  { type: "document", label: "Document", icon: FileText },
];

const EXAMPLE_MESSAGE =
  "URGENT: Your bank account will be suspended in 2 hours. Verify your KYC immediately by clicking this link and entering your PIN: bit.ly/kyc-verify-now";

export function AnalyzeForm() {
  const router = useRouter();
  const [type, setType] = useState<AnalyzeType>("message");
  const [inputValue, setInputValue] = useState("");
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const isUpload = type === "image" || type === "document";
  const disabled = submitting || (isUpload ? !uploadedFile : !inputValue.trim());

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragOver(false);
    const file = event.dataTransfer.files[0];
    if (file) setUploadedFile(file);
  }

  async function handleAnalyze() {
    setError(null);
    setSubmitting(true);
    try {
      const report =
        type === "message"
          ? await analyzeText(inputValue)
          : type === "link"
            ? await analyzeLink(inputValue)
            : await analyzeUpload(uploadedFile as File);

      sessionStorage.setItem(`rk_report:${report.investigation_id}`, JSON.stringify(report));
      router.push(`/analyze/investigating?id=${report.investigation_id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Analysis failed — please try again");
      setSubmitting(false);
    }
  }

  return (
    <div className="grid gap-6 md:grid-cols-[1.7fr_1fr]" style={{ animation: "rk-fade .4s ease both" }}>
      <div>
        <div className="relative flex border-b-2 border-border">
          {TABS.map(({ type: t, label, icon: Icon }) => (
            <button
              key={t}
              type="button"
              onClick={() => setType(t)}
              className={cn(
                "flex flex-1 items-center justify-center gap-2 py-3 font-heading text-sm font-extrabold",
                type === t ? "text-primary" : "text-foreground"
              )}
            >
              <Icon className="size-4" strokeWidth={1.8} />
              {label}
            </button>
          ))}
          <div
            className="absolute -bottom-0.5 h-[3px] w-1/4 bg-primary transition-[left] duration-200"
            style={{ left: `${TABS.findIndex((t) => t.type === type) * 25}%` }}
          />
        </div>

        <div className="mt-4">
          {type === "message" && (
            <div>
              <Textarea
                rows={9}
                placeholder="Paste the suspicious message text here…"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
              />
              <div className="mt-1.5 flex items-center justify-between">
                <Button
                  variant="ghost"
                  className="px-0 text-xs text-primary hover:text-primary"
                  onClick={() => setInputValue(EXAMPLE_MESSAGE)}
                >
                  Try an example scam message →
                </Button>
                <span className="text-xs text-muted-rk">{inputValue.length} characters</span>
              </div>
            </div>
          )}

          {type === "link" && (
            <div className="grid gap-1.5">
              <label className="text-xs text-foreground/80">URL</label>
              <Input placeholder="https://…" value={inputValue} onChange={(e) => setInputValue(e.target.value)} />
              <p className="mt-1.5 text-xs text-muted-rk">
                Rakshak checks domain age, reputation, redirects, and campaign matches — it never opens the link on your device.
              </p>
            </div>
          )}

          {isUpload && (
            <div>
              <label
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                className={cn(
                  "block cursor-pointer border-2 border-dashed p-8 text-center text-muted-rk transition-colors",
                  dragOver ? "border-primary bg-accent" : "border-border bg-transparent"
                )}
              >
                <input
                  type="file"
                  accept={type === "image" ? "image/*" : "application/pdf"}
                  className="hidden"
                  onChange={(e) => e.target.files?.[0] && setUploadedFile(e.target.files[0])}
                />
                {type === "image" ? <ImageIcon className="mx-auto mb-2 size-7" strokeWidth={1.5} /> : <FileText className="mx-auto mb-2 size-7" strokeWidth={1.5} />}
                {dragOver ? "Drop it here" : type === "image" ? "Drag and drop a screenshot, or click to upload" : "Drop a PDF, or click to upload"}
              </label>
              {uploadedFile && (
                <div className="mt-2 flex items-center justify-between bg-muted px-3 py-2 text-[13px]">
                  <span>📎 {uploadedFile.name}</span>
                  <Button variant="ghost" className="px-0 text-xs" onClick={() => setUploadedFile(null)}>Remove</Button>
                </div>
              )}
            </div>
          )}
        </div>

        {error && <p className="mt-2 text-xs text-destructive">{error}</p>}

        <Button disabled={disabled} className="mt-4 h-12 w-full justify-center text-[15px]" onClick={handleAnalyze}>
          {submitting ? "Analyzing…" : "Analyze with Rakshak"}
        </Button>
        <p className="mt-2 text-center text-xs text-muted-rk">No WhatsApp or Telegram connection required.</p>
      </div>

      <div className="flex flex-col gap-4">
        <Card className="elev-sm items-center p-4 text-center">
          <CardContent className="flex flex-col items-center gap-2 p-0">
            <IntelligenceCore size={110} />
            <div className="font-heading text-[11px] font-extrabold tracking-[0.06em] text-[var(--rk-accent-700)]">
              {inputValue || uploadedFile ? "READY TO INVESTIGATE" : "STANDING BY"}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex flex-col gap-2">
            <div className="text-[10px] font-extrabold tracking-[0.1em] text-primary uppercase">What Rakshak checks</div>
            {analyzeChecklist[type].map((item) => (
              <div key={item} className="flex items-center gap-2 text-[13px]">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" strokeWidth={2.4} className="flex-none">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
                {item}
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
