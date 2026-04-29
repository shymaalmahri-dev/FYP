import { ENV } from "./env";
import { checkDatabaseHealth } from "../db";

export async function checkOllamaHealth() {
  try {
    const response = await fetch(`${ENV.ollamaBaseUrl.replace(/\/$/, "")}/api/tags`);
    if (!response.ok) {
      return {
        ok: false,
        message: `HTTP ${response.status} from Ollama`,
      };
    }

    const data = (await response.json()) as {
      models?: Array<{ name?: string; model?: string }>;
    };

    const models = Array.isArray(data.models) ? data.models : [];
    const modelReady = models.some(model => {
      const name = model.name || model.model || "";
      return name.includes(ENV.ollamaModel);
    });

    return {
      ok: modelReady,
      message: modelReady
        ? `Model ${ENV.ollamaModel} available`
        : `Ollama reachable but model ${ENV.ollamaModel} not installed`,
    };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Ollama unavailable",
    };
  }
}

export async function getSystemStatus() {
  const database = await checkDatabaseHealth();
  const ollama = await checkOllamaHealth();

  return {
    ok: database.ok,
    runtime: {
      ingestionMode: ENV.enableFileAlertIngestion ? "file-backfill" : "direct-post",
      ollamaModel: ENV.ollamaModel,
    },
    services: {
      detectionEngine: {
        ok: true,
        message: "Dashboard server is running",
      },
      database,
      ollama,
      websocket: {
        ok: true,
        message: "Socket.IO server initialized with dashboard process",
      },
    },
    checkedAt: new Date().toISOString(),
  };
}
