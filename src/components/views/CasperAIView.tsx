import { useEffect, useRef, useState } from "react";
import { Sparkles, Send, RotateCcw, AlertCircle } from "lucide-react";
import { useCasperAI } from "../../lib/casper-ai";
import { useWorkspace } from "../../lib/workspace";

const SUGGESTED_QUESTIONS = [
  "What are my highest-risk findings?",
  "Which assets need attention first?",
  "What are my biggest security risks?",
  "What changed since my last scan?",
  "Give me a summary of my current security posture.",
  "Create a remediation plan for my critical findings.",
  "Give me a management summary of our security posture.",
  "What should my team fix this week?",
];

export function CasperAIView() {
  const { organization } = useWorkspace();
  const { messages, isLoading, error, sendMessage, clearConversation } = useCasperAI();
  const [inputValue, setInputValue] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom of messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSendMessage = async (text: string = inputValue) => {
    if (!organization || !text.trim() || isLoading) return;
    await sendMessage(text, organization.id);
    setInputValue("");
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
    // Shift+Enter creates newline (default browser behavior)
  };

  const handleSuggestedQuestion = (question: string) => {
    setInputValue(question);
    setTimeout(() => inputRef.current?.focus(), 0);
  };

  return (
    <div className="casper-ai-container">
      {/* Header Section */}
      <div className="casper-ai-header">
        <div className="casper-ai-header-content">
          <div className="flex-1">
            <h2 className="casper-ai-title">
              <Sparkles size={20} />
              CASPER AI
            </h2>
            <p className="casper-ai-subtitle">Security intelligence. Know what matters. Fix what matters first.</p>
          </div>
          {messages.length > 0 && (
            <button className="btn btn-ghost btn-sm" onClick={clearConversation} title="Clear conversation">
              <RotateCcw size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Chat Area */}
      <div className="casper-ai-chat">
        {messages.length === 0 ? (
          <div className="casper-ai-empty">
            <div className="casper-ai-empty-icon">
              <Sparkles size={32} />
            </div>
            <h3>Ask about your security posture</h3>
            <p>CASPER AI analyzes your real security data to answer questions about what matters most.</p>
            <div className="casper-ai-suggestions">
              <div className="casper-ai-suggestions-label">Suggested Questions:</div>
              <div className="casper-ai-suggestion-grid">
                {SUGGESTED_QUESTIONS.map((question, index) => (
                  <button
                    key={index}
                    className="casper-ai-suggestion-btn"
                    onClick={() => handleSuggestedQuestion(question)}
                  >
                    {question}
                  </button>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="casper-ai-messages">
            {messages.map((msg) => (
              <div key={msg.id} className={`casper-ai-message casper-ai-message-${msg.role}`}>
                <div className="casper-ai-message-avatar">
                  {msg.role === "user" ? (
                    <span className="casper-ai-user-avatar">U</span>
                  ) : (
                    <Sparkles size={16} />
                  )}
                </div>
                <div className="casper-ai-message-content">
                  <div className="casper-ai-message-text">{msg.content}</div>
                  <div className="casper-ai-message-time">
                    {msg.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </div>
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="casper-ai-message casper-ai-message-assistant casper-ai-message-loading">
                <div className="casper-ai-message-avatar">
                  <Sparkles size={16} />
                </div>
                <div className="casper-ai-message-content">
                  <div className="casper-ai-message-text">
                    <div className="casper-ai-typing-indicator">
                      <span></span>
                      <span></span>
                      <span></span>
                    </div>
                  </div>
                </div>
              </div>
            )}
            {error && (
              <div className="casper-ai-error">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        )}
      </div>

      {/* Input Section */}
      <div className="casper-ai-input-section">
        <div className="casper-ai-input-wrapper">
          <textarea
            ref={inputRef}
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask a question about your security posture... (Shift+Enter for newline)"
            className="casper-ai-input"
            disabled={isLoading}
            rows={1}
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={isLoading || !inputValue.trim()}
            className="casper-ai-send-btn"
            title="Send message"
          >
            <Send size={16} />
          </button>
        </div>
        <div className="casper-ai-input-hint">
          CASPER AI analyzes your workspace data and never invents vulnerabilities or assets.
        </div>
      </div>
    </div>
  );
}
