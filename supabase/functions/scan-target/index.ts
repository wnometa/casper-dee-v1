import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface ScanFinding {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  cvss_score: number;
  evidence: string;
  remediation: string;
  is_externally_exposed: boolean;
}

const SECURITY_HEADERS: Record<string, { severity: ScanFinding["severity"]; cvss: number; title: string; desc: string; fix: string }> = {
  "strict-transport-security": {
    severity: "high",
    cvss: 7.4,
    title: "Missing Strict-Transport-Security (HSTS) header",
    desc: "The server does not send the HSTS header, allowing downgrade attacks where an attacker forces a victim to connect over plain HTTP.",
    fix: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
  },
  "content-security-policy": {
    severity: "high",
    cvss: 6.1,
    title: "Missing Content-Security-Policy (CSP) header",
    desc: "Without CSP, the browser executes any inline script on the page, making cross-site scripting (XSS) far more exploitable.",
    fix: "Define a restrictive CSP like: default-src 'self'; script-src 'self'; object-src 'none'.",
  },
  "x-frame-options": {
    severity: "medium",
    cvss: 4.3,
    title: "Missing X-Frame-Options header",
    desc: "The page can be embedded in an iframe by any origin, enabling clickjacking attacks where a user is tricked into interacting with hidden elements.",
    fix: "Add 'X-Frame-Options: DENY' or use CSP 'frame-ancestors' to restrict embedding.",
  },
  "x-content-type-options": {
    severity: "low",
    cvss: 3.1,
    title: "Missing X-Content-Type-Options header",
    desc: "Without 'nosniff', browsers may MIME-sniff responses and execute content as a type not intended by the server.",
    fix: "Add 'X-Content-Type-Options: nosniff' to all responses.",
  },
  "referrer-policy": {
    severity: "low",
    cvss: 2.0,
    title: "Missing Referrer-Policy header",
    desc: "The browser may leak the full URL as a referrer to third-party origins, exposing internal paths and query parameters.",
    fix: "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
  },
  "permissions-policy": {
    severity: "low",
    cvss: 2.0,
    title: "Missing Permissions-Policy header",
    desc: "Browser features like camera, microphone, and geolocation are not restricted, allowing third-party embeds to access them.",
    fix: "Add a Permissions-Policy restricting unused features, e.g. 'camera=(), microphone=(), geolocation=()'.",
  },
};

function normalizeUrl(input: string): string {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }
  return url;
}

function parseHeaders(rawHeaders: Headers): Record<string, string> {
  const headers: Record<string, string> = {};
  rawHeaders.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  return headers;
}

function analyzeHeaders(headers: Record<string, string>): ScanFinding[] {
  const findings: ScanFinding[] = [];

  for (const [headerName, info] of Object.entries(SECURITY_HEADERS)) {
    if (!headers[headerName]) {
      findings.push({
        title: info.title,
        description: info.desc,
        severity: info.severity,
        cvss_score: info.cvss,
        evidence: `Response does not include the "${headerName}" header.`,
        remediation: info.fix,
        is_externally_exposed: true,
      });
    }
  }

  const serverHeader = headers["server"];
  if (serverHeader && /\d/.test(serverHeader)) {
    findings.push({
      title: "Server software version disclosed",
      description: `The Server header reveals "${serverHeader}", which exposes the server software and version. Attackers use this to identify known vulnerabilities for that specific version.`,
      severity: "low",
      cvss_score: 3.7,
      evidence: `Server: ${serverHeader}`,
      remediation: "Configure the web server to suppress version information in the Server header, or replace it with a generic value.",
      is_externally_exposed: true,
    });
  }

  const xPoweredBy = headers["x-powered-by"];
  if (xPoweredBy) {
    findings.push({
      title: "X-Powered-By header exposes technology stack",
      description: `The X-Powered-By header reveals "${xPoweredBy}", disclosing the backend framework. Attackers use this to target known vulnerabilities in that framework.`,
      severity: "low",
      cvss_score: 3.1,
      evidence: `X-Powered-By: ${xPoweredBy}`,
      remediation: "Disable the X-Powered-By header in your framework or reverse proxy configuration.",
      is_externally_exposed: true,
    });
  }

  return findings;
}

function analyzeHtml(html: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  const inlineScripts = html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi);
  if (inlineScripts && inlineScripts.length > 0) {
    findings.push({
      title: `${inlineScripts.length} inline <script> block(s) detected`,
      description: "Inline scripts execute without a CSP nonce or hash, making XSS exploitation easier. If an attacker can inject HTML, they can execute arbitrary JavaScript.",
      severity: "medium",
      cvss_score: 5.4,
      evidence: `Found ${inlineScripts.length} inline <script> tag(s) without a src attribute. First occurrence: ${inlineScripts[0].slice(0, 120)}…`,
      remediation: "Move inline scripts to external files, or enable CSP with nonces/hashes for inline scripts.",
      is_externally_exposed: true,
    });
  }

  const inlineEventHandlers = html.match(/\son\w+\s*=\s*["']/gi);
  if (inlineEventHandlers && inlineEventHandlers.length > 5) {
    findings.push({
      title: `${inlineEventHandlers.length} inline event handler(s) detected`,
      description: "Inline event handlers (onclick, onload, etc.) are blocked by a strong CSP and indicate potential XSS surface area.",
      severity: "low",
      cvss_score: 3.5,
      evidence: `Found ${inlineEventHandlers.length} inline event handler attributes. Example: ${inlineEventHandlers[0].trim()}`,
      remediation: "Move event handlers to addEventListener calls in external scripts.",
      is_externally_exposed: true,
    });
  }

  const formsWithHttp = html.match(/<form[^>]+action\s*=\s*["']http:\/\//gi);
  if (formsWithHttp && formsWithHttp.length > 0) {
    findings.push({
      title: "Form submits over insecure HTTP",
      description: "A form on the page submits data to an http:// URL, exposing submitted data to interception via man-in-the-middle attacks.",
      severity: "high",
      cvss_score: 7.5,
      evidence: `Found ${formsWithHttp.length} form(s) with an http:// action URL. Example: ${formsWithHttp[0].slice(0, 100)}`,
      remediation: "Change all form action URLs to https:// and enable HSTS to prevent downgrade.",
      is_externally_exposed: true,
    });
  }

  const passwordFields = html.match(/<input[^>]+type\s*=\s*["']password["'][^>]*>/gi);
  if (passwordFields && passwordFields.length > 0) {
    const formContext = html.match(/<form[^>]*>[\s\S]*?type\s*=\s*["']password["'][\s\S]*?<\/form>/gi);
    const hasAutocomplete = formContext?.some((f) => /autocomplete\s*=\s*["']off["']/i.test(f)) ?? false;
    if (!hasAutocomplete) {
      findings.push({
        title: "Password field without autocomplete disabled",
        description: "Password input fields do not have autocomplete='off', allowing browsers to store credentials which can be exfiltrated by malware or shared device users.",
        severity: "informational",
        cvss_score: 1.0,
        evidence: `Found ${passwordFields.length} password field(s). None are within a form with autocomplete='off'.`,
        remediation: "Add autocomplete='off' to password fields, or autocomplete='new-password' for registration forms.",
        is_externally_exposed: false,
      });
    }
  }

  const mixedContent = html.match(/(?:src|href)\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)/gi);
  if (mixedContent && mixedContent.length > 0) {
    findings.push({
      title: `${mixedContent.length} mixed-content resource(s) loaded over HTTP`,
      description: "The page loads scripts, images, or other resources over plain HTTP while served via HTTPS. Mixed content can be blocked by browsers or exploited for downgrade attacks.",
      severity: "medium",
      cvss_score: 4.3,
      evidence: `Found ${mixedContent.length} resource(s) with http:// URLs. Example: ${mixedContent[0].trim()}`,
      remediation: "Replace all http:// resource URLs with https:// equivalents.",
      is_externally_exposed: true,
    });
  }

  return findings;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const { target_id, target_value, organization_id, scan_job_id, user_id } = await req.json();

    if (!target_value || !organization_id || !scan_job_id) {
      return new Response(
        JSON.stringify({ error: "Missing required fields: target_value, organization_id, scan_job_id" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    );

    await supabase.from("scan_jobs").update({
      status: "running",
      started_at: new Date().toISOString(),
    }).eq("id", scan_job_id);

    const url = normalizeUrl(target_value);
    const findings: ScanFinding[] = [];
    let fetchError: string | null = null;
    let finalUrl = url;
    let statusCode = 0;

    try {
      const response = await fetch(url, {
        method: "GET",
        redirect: "follow",
        headers: { "User-Agent": "CASPER-DEE-Security-Scanner/1.0" },
        signal: AbortSignal.timeout(15000),
      });

      statusCode = response.status;
      finalUrl = response.url;

      if (!response.ok && response.status >= 400) {
        findings.push({
          title: `Server returned HTTP ${response.status} error`,
          description: `The server responded with status ${response.status} (${response.statusText}). This may indicate a misconfiguration, an unprotected admin endpoint, or an error page leaking stack traces.`,
          severity: response.status >= 500 ? "medium" : "informational",
          cvss_score: response.status >= 500 ? 4.3 : 1.0,
          evidence: `HTTP ${response.status} ${response.statusText} from ${url}`,
          remediation: "Ensure error pages do not leak internal details and that the endpoint is intended to be publicly accessible.",
          is_externally_exposed: true,
        });
      }

      const headers = parseHeaders(response.headers);
      findings.push(...analyzeHeaders(headers));

      const contentType = headers["content-type"] ?? "";
      if (contentType.includes("text/html")) {
        const html = await response.text();
        const truncatedHtml = html.slice(0, 500000);
        findings.push(...analyzeHtml(truncatedHtml));
      }

      if (finalUrl !== url && !finalUrl.startsWith("https://")) {
        findings.push({
          title: "HTTPS to HTTP redirect detected",
          description: `The server redirected from ${url} to ${finalUrl}, downgrading from HTTPS to insecure HTTP. This exposes all subsequent traffic to interception.`,
          severity: "high",
          cvss_score: 7.4,
          evidence: `Redirected from ${url} to ${finalUrl}`,
          remediation: "Ensure all redirects point to https:// URLs and enable HSTS to prevent downgrade.",
          is_externally_exposed: true,
        });
      }
    } catch (err) {
      fetchError = err instanceof Error ? err.message : String(err);
      findings.push({
        title: "Target unreachable or connection failed",
        description: `The scanner could not establish a connection to ${url}. This may indicate the host is down, DNS does not resolve, a firewall is blocking the request, or the TLS certificate is invalid.`,
        severity: "medium",
        cvss_score: 4.0,
        evidence: `Connection error: ${fetchError}`,
        remediation: "Verify the target URL is correct and accessible from the public internet. Check DNS resolution, firewall rules, and TLS certificate validity.",
        is_externally_exposed: false,
      });
    }

    const insertedFindings: { id: string }[] = [];
    for (const f of findings) {
      const { data, error } = await supabase.from("findings").insert({
        organization_id,
        asset_id: null,
        scan_job_id,
        title: f.title,
        description: f.description,
        severity: f.severity,
        status: "open",
        cvss_score: f.cvss_score,
        is_externally_exposed: f.is_externally_exposed,
        evidence: f.evidence,
        remediation: f.remediation,
      }).select("id").single();

      if (!error && data) {
        insertedFindings.push(data);
      }
    }

    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const highCount = findings.filter((f) => f.severity === "high").length;
    const mediumCount = findings.filter((f) => f.severity === "medium").length;
    const lowCount = findings.filter((f) => f.severity === "low").length;
    const infoCount = findings.filter((f) => f.severity === "informational").length;

    const summaryParts: string[] = [];
    if (criticalCount) summaryParts.push(`${criticalCount} critical`);
    if (highCount) summaryParts.push(`${highCount} high`);
    if (mediumCount) summaryParts.push(`${mediumCount} medium`);
    if (lowCount) summaryParts.push(`${lowCount} low`);
    if (infoCount) summaryParts.push(`${infoCount} informational`);

    const summary = findings.length === 0
      ? `Assessment of ${target_value} completed. No security issues detected — the target has strong security headers and no inline script or mixed-content issues.`
      : `Assessment of ${target_value} completed. ${findings.length} finding(s): ${summaryParts.join(", ")}.`;

    await supabase.from("scan_jobs").update({
      status: "completed",
      completed_at: new Date().toISOString(),
      findings_count: findings.length,
      summary,
    }).eq("id", scan_job_id);

    await supabase.from("audit_logs").insert({
      organization_id,
      actor_id: user_id ?? null,
      action: "scan.completed",
      resource_type: "scan_target",
      resource_id: target_id ?? null,
      metadata: { target: target_value, findings: findings.length, status_code: statusCode },
    });

    return new Response(
      JSON.stringify({
        status: "completed",
        target: target_value,
        final_url: finalUrl,
        status_code: statusCode,
        findings_count: findings.length,
        summary,
        findings: findings.map((f) => ({ title: f.title, severity: f.severity, evidence: f.evidence })),
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Scan failed unexpectedly";
    return new Response(
      JSON.stringify({ error: "The scan could not be completed. Please try again." }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  }
});
