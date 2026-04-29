type EdgeBlockResponse = {
  success: boolean;
  message: string;
  blockedIp?: string;
  mode: "agent" | "disabled";
};

const EDGE_BLOCK_AGENT_URL = process.env.EDGE_BLOCK_AGENT_URL?.trim() || "";
const EDGE_BLOCK_AGENT_TOKEN = process.env.EDGE_BLOCK_AGENT_TOKEN?.trim() || "";

export function getEdgeBlockMode(): "agent" | "disabled" {
  return EDGE_BLOCK_AGENT_URL ? "agent" : "disabled";
}

async function callEdgeAgent(
  path: string,
  ipAddress: string,
  reason?: string,
): Promise<EdgeBlockResponse> {
  if (!EDGE_BLOCK_AGENT_URL) {
    return {
      success: false,
      message:
        "EDGE_BLOCK_AGENT_URL is not configured. Blocking is dashboard-only until the edge block agent is enabled.",
      mode: "disabled",
    };
  }

  try {
    const targetUrl = new URL(EDGE_BLOCK_AGENT_URL);
    targetUrl.pathname = path;

    const response = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(EDGE_BLOCK_AGENT_TOKEN
          ? { Authorization: `Bearer ${EDGE_BLOCK_AGENT_TOKEN}` }
          : {}),
      },
      body: JSON.stringify({
        ipAddress,
        reason: reason ?? "Blocked from ELAI dashboard",
      }),
    });

    const payload = (await response.json().catch(() => ({}))) as {
      success?: boolean;
      message?: string;
      blockedIp?: string;
    };

    if (!response.ok || !payload.success) {
      return {
        success: false,
        message:
          payload.message ||
          `Edge block agent returned HTTP ${response.status}`,
        blockedIp: payload.blockedIp,
        mode: "agent",
      };
    }

    return {
      success: true,
      message: payload.message || `${ipAddress} blocked on edge agent`,
      blockedIp: payload.blockedIp ?? ipAddress,
      mode: "agent",
    };
  } catch (error) {
    return {
      success: false,
      message:
        error instanceof Error
          ? error.message
          : "Failed to reach edge block agent",
      mode: "agent",
    };
  }
}

export async function enforceEdgeBlock(
  ipAddress: string,
  reason?: string,
): Promise<EdgeBlockResponse> {
  return callEdgeAgent("/block-ip", ipAddress, reason);
}

export async function enforceEdgeUnblock(
  ipAddress: string,
  reason?: string,
): Promise<EdgeBlockResponse> {
  return callEdgeAgent("/unblock-ip", ipAddress, reason);
}
