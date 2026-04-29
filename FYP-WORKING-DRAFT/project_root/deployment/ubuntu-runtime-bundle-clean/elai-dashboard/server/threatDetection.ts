import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { createAlert } from "./db";
import { broadcastAlert } from "./websocket";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "../..");

const ALERTS_FILE = path.join(PROJECT_ROOT, "explainable_ai/alerts/alerts_log.json");
const EXPLANATIONS_FILE = path.join(PROJECT_ROOT, "explainable_ai/reports/explanations.json");
const INCIDENTS_FILE = path.join(PROJECT_ROOT, "explainable_ai/genai_reports/incident_reports.json");

const processedAlertKeys = new Set<string>();

function loadJSON(filePath: string) {
  try {
    if (!fs.existsSync(filePath)) {
      return [];
    }

    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw);
  } catch (error) {
    console.error(`[ThreatDetection] Error loading ${filePath}:`, error);
    return [];
  }
}

function buildShapExplanation(explanation: any, features: Record<string, unknown>) {
  const topFeatures = Array.isArray(explanation?.top_features) ? explanation.top_features : [];

  return JSON.stringify({
    baseValue: 0.5,
    prediction: 0.95,
    features: topFeatures.map((item: any) => {
      const name = item?.feature || item?.name || "unknown";
      return {
        name,
        importance: Math.abs(Number(item?.impact ?? item?.importance ?? 0)),
        value: features?.[name] != null ? String(features[name]) : "",
      };
    }),
  });
}

function inferSeverity(attackType: string) {
  if (["SQL_Injection", "Directory_Traversal", "Command_Injection", "XSS_Injection"].includes(attackType)) {
    return "critical";
  }

  if (attackType.includes("Brute_Force") || attackType.includes("Scan")) {
    return "medium";
  }

  return "high";
}

function buildAlertRecord(alert: any, explanation: any, incident: any, index: number) {
  const features = alert?.features ?? {};
  const protocol = features?.ip_proto != null ? String(features.ip_proto) : "TCP";

  return {
    id: index + 1,
    timestamp: new Date(alert.timestamp),
    severity: inferSeverity(String(alert.attack_type || "Unknown")),
    threatType: alert.attack_type,
    sourceIp: alert.attacker_ip,
    destinationIp: alert.destination_ip || "unknown",
    port: features?.dport ? Number(features.dport) : 0,
    protocol,
    description: incident?.report || null,
    modelConfidence: "95",
    isBlocked: 0,
    shapeExplanation: explanation ? buildShapExplanation(explanation, features) : null,
    llmExplanation: incident?.report || null,
  };
}

function loadExplainableThreatsInternal() {
  const alerts = loadJSON(ALERTS_FILE);
  const explanations = loadJSON(EXPLANATIONS_FILE);
  const incidents = loadJSON(INCIDENTS_FILE);

  return alerts.map((alert: any, index: number) => {
    const explanation = explanations.find((item: any) => item.timestamp === alert.timestamp);
    const incident = incidents.find((item: any) => item.timestamp === alert.timestamp);
    const alertKey = `${alert.timestamp}-${alert.attacker_ip}-${alert.attack_type}`;

    return {
      alertKey,
      fullAlert: buildAlertRecord(alert, explanation, incident, index),
    };
  });
}

export function getExplainableThreats() {
  return loadExplainableThreatsInternal().map((item: { fullAlert: ReturnType<typeof buildAlertRecord> }) => item.fullAlert);
}

export async function ingestNewExplainableThreats() {
  const newAlerts = loadExplainableThreatsInternal()
    .filter(({ alertKey }: { alertKey: string }) => {
      if (processedAlertKeys.has(alertKey)) {
        return false;
      }

      processedAlertKeys.add(alertKey);
      return true;
    })
    .map(({ fullAlert }: { fullAlert: ReturnType<typeof buildAlertRecord> }) => fullAlert);

  for (const fullAlert of newAlerts) {
    try {
      const storedAlert = await createAlert(fullAlert as any);
      broadcastAlert(storedAlert ?? fullAlert);
    } catch (error) {
      console.warn("[ThreatDetection] Failed to persist alert:", error);
    }
  }

  return newAlerts;
}
