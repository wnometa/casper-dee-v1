import { useState, useCallback, useRef } from "react";
import { useAuth } from "./auth";

export interface CasperAIMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface UseCasperAIReturn {
  messages: CasperAIMessage[];
  isLoading: boolean;
  error: string | null;
  sendMessage: (message: string, organizationId: string) => Promise<void>;
  clearConversation: () => void;
}

export function useCasperAI(): UseCasperAIReturn {
  const { session } = useAuth();
  const [messages, setMessages] = useState<CasperAIMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messageIdRef = useRef(0);

  const sendMessage = useCallback(
    async (message: string, organizationId: string) => {
      if (!session) {
        setError("Not authenticated");
        return;
      }

      if (!message.trim()) {
        return;
      }

      // Add user message to conversation
      const userMessage: CasperAIMessage = {
        id: `msg-${messageIdRef.current++}`,
        role: "user",
        content: message,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, userMessage]);
      setError(null);
      setIsLoading(true);

      try {
        // Get the current session token
        const token = session.access_token;

        if (!token) {
          throw new Error("No authentication token available");
        }

        // Prepare conversation history for context
        const conversationHistory = messages.map((msg) => ({
          role: msg.role as "user" | "assistant",
          content: msg.content,
        }));

        // Call CASPER AI endpoint
        const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/casper-ai`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            message: message,
            organizationId: organizationId,
            conversationHistory: conversationHistory,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || "Failed to get AI response");
        }

        const responseData = await response.json();

        // Add AI response to conversation
        const aiMessage: CasperAIMessage = {
          id: `msg-${messageIdRef.current++}`,
          role: "assistant",
          content: responseData.response,
          timestamp: new Date(),
        };
        setMessages((prev) => [...prev, aiMessage]);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : "Failed to send message";
        setError(errorMsg);
        console.error("CASPER AI error:", errorMsg);
      } finally {
        setIsLoading(false);
      }
    },
    [session, messages]
  );

  const clearConversation = useCallback(() => {
    setMessages([]);
    setError(null);
    messageIdRef.current = 0;
  }, []);

  return {
    messages,
    isLoading,
    error,
    sendMessage,
    clearConversation,
  };
}
