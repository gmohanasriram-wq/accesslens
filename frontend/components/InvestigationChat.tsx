"use client";

import { useEffect, useRef, useState } from "react";
import type { ChatMessage, EvidenceCitation, InvestigationChatResponse } from "@/types/api";
import { fetchInvestigationChat } from "@/lib/api";
import { Stamp } from "@/components/ui";
import { cx } from "@/lib/cx";

interface StoredMessage extends ChatMessage {
  citations?: EvidenceCitation[];
  isFallback?: boolean;
  providerInfo?: string;
}

interface InvestigationChatProps {
  findingId: string;
  subjectName: string;
  initialProviderInfo?: string;
}

function getPersonaPromptChips(subjectName: string): string[] {
  const lower = subjectName.toLowerCase();
  if (lower.includes("bob") || lower.includes("u_bob")) {
    return [
      "Why was Bob flagged for AdministratorAccess?",
      "What specific AWS capabilities did Bob actually use?",
      "What is Bob's privilege utilization ratio?",
    ];
  }
  if (lower.includes("carol") || lower.includes("u_carol")) {
    return [
      "What happened after Carol's Okta account was disabled?",
      "Which GitHub actions were recorded post-deactivation?",
      "Are personal access tokens still active?",
    ];
  }
  if (lower.includes("gina") || lower.includes("u_gina")) {
    return [
      "Did Gina use her application access?",
      "Why is proxy telemetry missing?",
      "Can any determination be made without proxy logs?",
    ];
  }
  return [
    "Explain the factual basis for this finding",
    "What exhibits support this finding?",
    "What evidence gaps or uncertainties exist?",
  ];
}

export function InvestigationChat({
  findingId,
  subjectName,
  initialProviderInfo = "deterministic-mock-v1",
}: InvestigationChatProps) {
  const [messages, setMessages] = useState<StoredMessage[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [providerInfo, setProviderInfo] = useState(initialProviderInfo);
  const [isFallback, setIsFallback] = useState(false);
  const [suggestedFollowups, setSuggestedFollowups] = useState<string[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const chatStorageKey = `accesslens_chat_${findingId}`;

  // Restore chat history from sessionStorage
  useEffect(() => {
    try {
      const saved = sessionStorage.getItem(chatStorageKey);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          setMessages(parsed);
          const lastAssistant = [...parsed].reverse().find((m) => m.role === "assistant");
          if (lastAssistant) {
            if (lastAssistant.providerInfo) setProviderInfo(lastAssistant.providerInfo);
            if (typeof lastAssistant.isFallback === "boolean") setIsFallback(lastAssistant.isFallback);
          }
        }
      }
    } catch {
      // Storage unavailable or corrupted; proceed with empty state
    }
  }, [chatStorageKey]);

  // Persist messages to sessionStorage
  useEffect(() => {
    try {
      if (messages.length > 0) {
        sessionStorage.setItem(chatStorageKey, JSON.stringify(messages));
      } else {
        sessionStorage.removeItem(chatStorageKey);
      }
    } catch {
      // Ignore quota errors
    }
  }, [messages, chatStorageKey]);

  // Scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isLoading]);

  const promptChips = getPersonaPromptChips(subjectName);

  const handleSend = async (messageText: string) => {
    const text = messageText.trim();
    if (!text || isLoading) return;

    setError(null);
    setInput("");

    const newHistory: ChatMessage[] = messages.slice(-6).map((m) => ({
      role: m.role,
      content: m.content,
    }));

    const userMessage: StoredMessage = { role: "user", content: text };
    const updatedMessages = [...messages, userMessage];
    setMessages(updatedMessages);
    setIsLoading(true);

    try {
      const res: InvestigationChatResponse = await fetchInvestigationChat(
        findingId,
        text,
        newHistory,
      );

      const assistantMessage: StoredMessage = {
        role: "assistant",
        content: res.reply,
        citations: res.citations,
        isFallback: res.is_fallback,
        providerInfo: res.provider_info,
      };

      setMessages([...updatedMessages, assistantMessage]);
      setProviderInfo(res.provider_info);
      setIsFallback(res.is_fallback);
      setSuggestedFollowups(res.suggested_followups ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to obtain response");
    } finally {
      setIsLoading(false);
    }
  };

  const handleCitationClick = (evidenceId: string) => {
    const el = document.getElementById(`exhibit-${evidenceId}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.classList.add("ring-2", "ring-accent", "transition-all");
      setTimeout(() => {
        el.classList.remove("ring-2", "ring-accent");
      }, 2500);
    }
  };

  const handleClear = () => {
    setMessages([]);
    setError(null);
    setSuggestedFollowups([]);
    sessionStorage.removeItem(chatStorageKey);
  };

  return (
    <div
      data-testid="investigation-chat"
      className="border border-rule bg-card px-3.5 py-3 sm:px-5 sm:py-4"
    >
      {/* Header with Title and Disclosure Badge */}
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2 border-b border-rule pb-3">
        <div>
          <h3 className="font-display text-sm tracking-tight text-ink sm:text-base">
            Interactive Cross-Examination
          </h3>
          <p className="mt-0.5 font-mono text-[10px] tracking-[0.12em] text-faint uppercase">
            Contextual Q&amp;A Grounded Strictly in Finding Exhibits
          </p>
        </div>

        <div className="flex items-center gap-2" data-testid="chat-provider-badge">
          {isFallback ? (
            <Stamp className="border-signal bg-signal-ground text-signal font-medium">
              ⚠ NVIDIA unavailable — deterministic local response
            </Stamp>
          ) : providerInfo.toLowerCase().includes("nvidia") ? (
            <Stamp className="border-verified bg-verified-ground text-verified font-medium">
              NVIDIA Nemotron 3 Super · Live Cloud
            </Stamp>
          ) : (
            <Stamp className="border-rule bg-card-sunk text-muted">
              Deterministic Local Engine · Hermetic
            </Stamp>
          )}

          {messages.length > 0 && (
            <button
              type="button"
              onClick={handleClear}
              className="font-mono text-[10px] text-faint hover:text-ink underline ml-1 cursor-pointer"
            >
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Suggested Prompt Chips */}
      {messages.length === 0 && (
        <div className="mt-3.5">
          <p className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase mb-2">
            Suggested Investigative Questions:
          </p>
          <div className="flex flex-wrap gap-2">
            {promptChips.map((chip, idx) => (
              <button
                key={idx}
                type="button"
                data-testid="chat-prompt-chip"
                onClick={() => handleSend(chip)}
                className="border border-rule hover:border-accent/60 bg-card-sunk/60 hover:bg-card px-2.5 py-1.5 text-left font-mono text-xs text-ink transition-colors cursor-pointer"
              >
                {chip} →
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Conversation Messages */}
      <div
        data-testid="chat-messages"
        className="mt-4 space-y-4 max-h-[460px] overflow-y-auto pr-1"
      >
        {messages.length === 0 ? (
          <div className="border border-dashed border-rule/70 p-4 text-center">
            <p className="text-xs text-muted">
              Ask a question about {subjectName}&apos;s identity, granted privileges, telemetry records, or why this finding fired.
            </p>
            <p className="mt-1 font-mono text-[10px] text-faint">
              Zero autonomous modification. AccessLens never issues revocation commands.
            </p>
          </div>
        ) : (
          messages.map((msg, idx) => (
            <div
              key={idx}
              className={cx(
                "p-3 rounded-none text-xs leading-relaxed",
                msg.role === "user"
                  ? "border border-accent/30 bg-accent/5 ml-6"
                  : "border border-rule bg-card-sunk/70 mr-4",
              )}
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="font-mono text-[10px] tracking-[0.12em] uppercase font-semibold text-faint">
                  {msg.role === "user" ? "Reviewer Question" : "AI Trial Lawyer"}
                </span>
                {msg.role === "assistant" && (
                  <span className="font-mono text-[9px] text-faint uppercase">
                    {msg.isFallback
                      ? "Fallback"
                      : msg.providerInfo?.toLowerCase().includes("nvidia")
                        ? "NVIDIA Nemotron"
                        : "Deterministic"}
                  </span>
                )}
              </div>

              {/* Message Body */}
              <div className="text-ink whitespace-pre-wrap font-sans text-xs">
                {msg.content}
              </div>

              {/* Citations */}
              {msg.citations && msg.citations.length > 0 && (
                <div className="mt-3 border-t border-rule/50 pt-2">
                  <span className="font-mono text-[10px] tracking-[0.12em] text-faint uppercase block mb-1">
                    Cited Finding Exhibits:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {msg.citations.map((cit, cIdx) => (
                      <button
                        key={cIdx}
                        type="button"
                        data-testid={`citation-${cit.evidence_id}`}
                        data-evidence-id={cit.evidence_id}
                        onClick={() => handleCitationClick(cit.evidence_id)}
                        className="inline-flex items-center gap-1 border border-accent/40 bg-card px-2 py-0.5 font-mono text-[11px] text-accent hover:border-accent hover:bg-accent/10 transition-colors cursor-pointer"
                        title={cit.relevance}
                      >
                        <span>Exhibit {cit.evidence_id}</span>
                        <span className="text-[10px] text-muted">↗</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))
        )}

        {/* Loading Indicator */}
        {isLoading && (
          <div className="border border-rule bg-card-sunk/50 p-3 mr-4">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-accent animate-pulse" />
              <span className="font-mono text-xs text-muted">
                Analyzing finding exhibits and formulating grounded response...
              </span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Followups if available */}
      {suggestedFollowups.length > 0 && !isLoading && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-rule/40 pt-2">
          <span className="font-mono text-[10px] text-faint uppercase mr-1">Follow up:</span>
          {suggestedFollowups.map((followup, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleSend(followup)}
              className="border border-rule/70 hover:border-accent bg-card px-2 py-1 font-mono text-[11px] text-ink hover:text-accent transition-colors cursor-pointer"
            >
              {followup}
            </button>
          ))}
        </div>
      )}

      {/* Error Notice */}
      {error && (
        <div className="mt-3 border border-signal bg-signal-ground/30 px-3 py-2 text-xs text-signal">
          <p className="font-semibold">Query failed</p>
          <p className="font-mono text-[11px] mt-0.5">{error}</p>
        </div>
      )}

      {/* Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend(input);
        }}
        className="mt-3.5 flex gap-2"
      >
        <input
          type="text"
          data-testid="chat-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={`Ask about ${subjectName}'s permissions, activity, or exhibits...`}
          disabled={isLoading}
          className="flex-1 border border-rule bg-background px-3 py-2 font-mono text-xs text-ink placeholder:text-muted/60 focus:border-accent focus:outline-none disabled:opacity-50"
        />
        <button
          type="submit"
          data-testid="chat-submit"
          disabled={isLoading || !input.trim()}
          className="border border-rule bg-card px-4 py-2 font-mono text-xs text-ink hover:border-accent hover:bg-card-sunk focus:border-accent focus:outline-none disabled:opacity-40 disabled:hover:border-rule disabled:hover:bg-card cursor-pointer"
        >
          {isLoading ? "Querying..." : "Ask AI"}
        </button>
      </form>
    </div>
  );
}
