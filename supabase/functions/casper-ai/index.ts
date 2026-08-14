import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface CasperAIRequest {
  message: string;
  organizationId: string;
  conversationHistory?: Array<{ role: "user" | "assistant"; content: string }>;
}

interface CasperAIResponse {
  response: string;
  error?: string;
}

// System prompt that enforces anti-hallucination rules
const SYSTEM_PROMPT = `You are CASPER AI, a security decision assistant built into the CASPER DEE Security Decision Engine.

Your purpose is to help users understand what matters in their security posture and what they should prioritize.

CRITICAL RULES:
1. Only make factual claims about the user's workspace using the supplied security context data.
2. Never fabricate assets, vulnerabilities, CVEs, findings, incidents, scan results, security scores, or events.
3. If the available workspace data does not support an answer, clearly state: "I don't have enough workspace data to answer that confidently."
4. Always distinguish between OBSERVED (actual data from their workspace) and RECOMMENDATIONS (your analysis).

OBSERVED facts come directly from their security data:
- Assets (count, types, exposure state, criticality)
- Findings/vulnerabilities (severity, status, affected assets)
- Scan results and historical data
- Threat scenarios and attack paths
- Security scores and metrics

RECOMMENDATIONS are your analysis:
- Prioritization suggestions
- Remediation approaches
- Best practices
- Risk assessment

When answering questions:
1. Start with what you observe in their workspace
2. Explain why it matters
3. Recommend next steps
4. Suggest verification methods

Keep language business-friendly but technically accurate.
For managers: Use executive summary style.
For analysts: Provide technical details and evidence.

Never claim compliance, certification, or regulatory status unless their data explicitly supports it.
Never invent technical details not supported by their findings data.`;

async function getWorkspaceSecurityContext(
  supabaseClient: ReturnType<typeof createClient>,
  organizationId: string
): Promise<string> {
  try {
    // Fetch critical metrics from the organization's data
    const [assetsData, findingsData, threatsData, scanJobsData] = await Promise.all([
      supabaseClient
        .from("assets")
        .select("*")
        .eq("organization_id", organizationId)
        .limit(100),
      supabaseClient
        .from("findings")
        .select("id, title, severity, status, cvss_score, is_externally_exposed, asset_id, description")
        .eq("organization_id", organizationId)
        .order("severity", { ascending: false })
        .limit(50),
      supabaseClient
        .from("threat_scenarios")
        .select("*")
        .eq("organization_id", organizationId)
        .order("risk_score", { ascending: false })
        .limit(10),
      supabaseClient
        .from("scan_jobs")
        .select("*")
        .eq("organization_id", organizationId)
        .order("completed_at", { ascending: false })
        .limit(5),
    ]);

    // Build security context summary
    const assets = assetsData.data || [];
    const findings = findingsData.data || [];
    const threats = threatsData.data || [];
    const scans = scanJobsData.data || [];

    // Calculate finding statistics
    const findingsBySeverity = {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      informational: findings.filter((f) => f.severity === "informational").length,
    };

    const externallyExposed = findings.filter((f) => f.is_externally_exposed).length;
    const openFindings = findings.filter((f) => f.status === "open").length;

    // Asset statistics
    const assetsByType = {
      web: assets.filter((a) => a.asset_type === "web").length,
      server: assets.filter((a) => a.asset_type === "server").length,
      database: assets.filter((a) => a.asset_type === "database").length,
      cloud: assets.filter((a) => a.asset_type === "cloud").length,
      endpoint: assets.filter((a) => a.asset_type === "endpoint").length,
      network: assets.filter((a) => a.asset_type === "network").length,
    };

    const internetExposed = assets.filter((a) => a.exposure_state === "internet").length;
    const criticalAssets = assets.filter((a) => a.criticality === "critical").length;

    // Build context string
    let context = `# WORKSPACE SECURITY DATA\n\n`;
    context += `## Overview\n`;
    context += `- Total Assets: ${assets.length}\n`;
    context += `- Total Findings: ${findings.length} (${openFindings} open)\n`;
    context += `- Threat Scenarios: ${threats.length}\n`;
    context += `- Recent Scans: ${scans.length}\n\n`;

    context += `## Asset Distribution\n`;
    context += `- Web Applications: ${assetsByType.web}\n`;
    context += `- Servers: ${assetsByType.server}\n`;
    context += `- Databases: ${assetsByType.database}\n`;
    context += `- Cloud Resources: ${assetsByType.cloud}\n`;
    context += `- Endpoints: ${assetsByType.endpoint}\n`;
    context += `- Network: ${assetsByType.network}\n`;
    context += `- Internet-Exposed Assets: ${internetExposed}\n`;
    context += `- Critical Criticality: ${criticalAssets}\n\n`;

    context += `## Finding Severity Distribution\n`;
    context += `- Critical: ${findingsBySeverity.critical}\n`;
    context += `- High: ${findingsBySeverity.high}\n`;
    context += `- Medium: ${findingsBySeverity.medium}\n`;
    context += `- Low: ${findingsBySeverity.low}\n`;
    context += `- Informational: ${findingsBySeverity.informational}\n`;
    context += `- Externally Exposed Findings: ${externallyExposed}\n\n`;

    // Add top findings
    if (findings.length > 0) {
      context += `## Top Findings (by severity)\n`;
      findings.slice(0, 10).forEach((f) => {
        context += `- **${f.severity.toUpperCase()}**: ${f.title}`;
        if (f.cvss_score) context += ` (CVSS ${f.cvss_score})`;
        context += ` - Status: ${f.status}`;
        if (f.is_externally_exposed) context += ` [EXTERNALLY EXPOSED]`;
        context += `\n`;
      });
      context += `\n`;
    }

    // Add threat scenarios
    if (threats.length > 0) {
      context += `## Top Threat Scenarios\n`;
      threats.slice(0, 5).forEach((t) => {
        context += `- **${t.title}** (Risk Score: ${t.risk_score}/100) - Status: ${t.status}\n`;
        if (t.summary) context += `  ${t.summary}\n`;
      });
      context += `\n`;
    }

    // Add recent scan history
    if (scans.length > 0) {
      context += `## Recent Scans\n`;
      scans.forEach((s) => {
        const date = new Date(s.created_at).toLocaleDateString();
        context += `- ${date}: ${s.status} - ${s.findings_count} findings`;
        if (s.summary) context += ` - ${s.summary}`;
        context += `\n`;
      });
    }

    return context;
  } catch (error) {
    console.error("Error fetching workspace context:", error);
    return "## ERROR\nCould not fetch workspace security data. Please try again.";
  }
}

async function callGroq(
  systemPrompt: string,
  userMessage: string,
  workspaceContext: string,
  conversationHistory: Array<{ role: "user" | "assistant"; content: string }>
): Promise<string> {
  const apiKey = Deno.env.get("GROQ_API_KEY");

  if (!apiKey) {
    throw new Error("GROQ_API_KEY not configured in Supabase Edge Function secrets");
  }

  const messages: Array<{
    role: "system" | "user" | "assistant";
    content: string;
  }> = [
    {
      role: "system",
      content: `${systemPrompt}\n\n${workspaceContext}`,
    },
  ];

  if (conversationHistory?.length) {
    messages.push(...conversationHistory);
  }

  messages.push({
    role: "user",
    content: userMessage,
  });

  const response = await fetch(
    "https://api.groq.com/openai/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages,
        temperature: 0.4,
        max_tokens: 2000,
      }),
    }
  );

  const responseText = await response.text();

  if (!response.ok) {
    console.error("Groq API error:", response.status, responseText);

    let errorMessage = "Groq API request failed";

    try {
      const errorData = JSON.parse(responseText);
      errorMessage =
        errorData?.error?.message ||
        errorData?.message ||
        errorMessage;
    } catch {
      // Keep the generic error if the response isn't JSON.
    }

    throw new Error(errorMessage);
  }

  let data: any;

  try {
    data = JSON.parse(responseText);
  } catch {
    throw new Error("Invalid response received from Groq");
  }

  const content = data?.choices?.[0]?.message?.content;

  if (!content) {
    throw new Error("Groq returned an empty response");
  }

  return content;
}

async function handleRequest(req: Request): Promise<Response> {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // Only accept POST
    if (req.method !== "POST") {
      return new Response(
        JSON.stringify({ error: "Method not allowed" }),
        { status: 405, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    // Parse request body
    const body = (await req.json()) as CasperAIRequest;
    const { message, organizationId, conversationHistory = [] } = body;

    if (!message || !organizationId) {
      return new Response(
        JSON.stringify({ error: "Missing message or organizationId" }),
        { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    // Get authorization header to validate user
    const authHeader = req.headers.get("authorization");
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: "Unauthorized" }),
        { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    // Create Supabase client with user's session
    const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

    if (!supabaseUrl || !supabaseKey) {
      return new Response(
        JSON.stringify({ error: "Server configuration error" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    const supabaseClient = createClient(supabaseUrl, supabaseKey);

    // Verify user has access to this organization
    const token = authHeader.replace("Bearer ", "");
    const { data: userData } = await supabaseClient.auth.getUser(token);

    if (!userData.user) {
      return new Response(
        JSON.stringify({ error: "Invalid authentication" }),
        { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    // Check organization access
    const { data: orgAccess } = await supabaseClient
      .from("organization_members")
      .select("*")
      .eq("organization_id", organizationId)
      .eq("user_id", userData.user.id)
      .maybeSingle();

    if (!orgAccess) {
      return new Response(
        JSON.stringify({ error: "Access denied to organization" }),
        { status: 403, headers: { "Content-Type": "application/json", ...corsHeaders } }
      );
    }

    // Get workspace security context
    const workspaceContext = await getWorkspaceSecurityContext(supabaseClient, organizationId);

    // Call OpenAI API
    const aiResponse = await callGroq(SYSTEM_PROMPT, message, workspaceContext, conversationHistory);

    return new Response(
      JSON.stringify({ response: aiResponse } as CasperAIResponse),
      { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error("Error in CASPER AI endpoint:", errorMessage);

    // Safe error response - no sensitive details
    const response: CasperAIResponse = {
      response: "CASPER AI is temporarily unavailable. Your security data remains available in CASPER DEE.",
      error: "Internal server error",
    };

    return new Response(JSON.stringify(response), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
}

Deno.serve(handleRequest);
