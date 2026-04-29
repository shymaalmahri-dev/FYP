import { z } from "zod";
import { router, publicProcedure } from "../_core/trpc";

import {
  getAlerts,
  clearAlerts,
  getAlertById,
  getAlertsBySeverity,
  getAlertCount,
  updateAlert,
  markAlertsBlockedBySource,
  markAlertsUnblockedBySource,
  blockIp,
  getBlockedIps,
  isIpBlocked,
  unblockIp,
  getLatestSystemMetric,
  getSystemMetricsHistory,
} from "../db";

import { getExplainableThreats } from "../threatDetection";
import { generateDeepAnalysisWithPython } from "../_core/incidentGenerator";
import { extractExplanationFeatures } from "../_core/alertExplanation";
import { buildAlertsCsv, buildAlertsPdf } from "../_core/alertExport";
import { enforceEdgeBlock, enforceEdgeUnblock, getEdgeBlockMode } from "../_core/edgeBlockAgent";

function formatFeatureSummary(features: any[], limit = 3) {
  const picked = features
    .slice(0, limit)
    .map((f: any) => f.feature || f.name)
    .filter(Boolean);

  return picked.length > 0 ? picked.join(", ") : "network behavior indicators";
}

function buildFallbackAnalysis(alert: any, features: any[], verbosity: "brief" | "detailed" | "forensic") {
  const eventCategory = alert.eventCategory ?? "malicious";
  const primaryPrediction = alert.primaryPrediction || alert.threatType;
  const secondaryPrediction = alert.secondaryPrediction || "Normal";
  const confidence = alert.primaryConfidence || alert.modelConfidence || "0";
  const confidenceGap = alert.confidenceGap || "0";
  const featureSummary = formatFeatureSummary(features, verbosity === "forensic" ? 5 : 3);
  const blockLine =
    alert.blockStatus === "blocked"
      ? `Containment succeeded on ${alert.edgeDevice || "the edge device"} and the source is currently blocked.`
      : alert.blockStatus === "failed"
        ? `Containment was attempted but failed: ${alert.blockMessage || "the edge device rejected the block request"}.`
        : "No automatic containment was applied for this event.";

  if (eventCategory === "gray_zone") {
    if (verbosity === "brief") {
      return `This gray-zone event from ${alert.sourceIp} to ${alert.destinationIp} is leaning toward ${primaryPrediction} at ${confidence}% confidence, but the ${confidenceGap}% gap versus ${secondaryPrediction} is not strong enough for automatic blocking. Review the source, destination service, and nearby packet evidence before containment.`;
    }

    if (verbosity === "detailed") {
      return `This event was intentionally placed in the gray-zone review queue instead of being treated as a confirmed attack. The model currently leans toward ${primaryPrediction} at ${confidence}% confidence, with ${secondaryPrediction} as the nearest alternative and a confidence gap of ${confidenceGap}%. The strongest supporting indicators were ${featureSummary}. ${blockLine} Recommended analyst action: validate the traffic against host logs, packet captures, and any matching service activity before deciding to block or dismiss it.`;
    }

    return [
      `FORENSIC ANALYSIS - Gray Zone Review`,
      ``,
      `Attack Vector: Traffic from ${alert.sourceIp}:${alert.port || "unknown"} to ${alert.destinationIp} via ${alert.protocol || "unknown"}`,
      ``,
      `Classification Posture: Gray zone. Primary candidate=${primaryPrediction} (${confidence}%), secondary candidate=${secondaryPrediction}, confidence gap=${confidenceGap}%`,
      ``,
      `Key Indicators Detected: ${featureSummary}`,
      ``,
      `Containment Status: ${blockLine}`,
      ``,
      `Immediate Actions Required:`,
      `1. Compare this event with adjacent packets from the same source and destination.`,
      `2. Review application and host logs on the protected endpoint during the event window.`,
      `3. Escalate to containment only if corroborating evidence confirms malicious intent.`,
    ].join("\n");
  }

  if (eventCategory === "normal") {
    if (verbosity === "brief") {
      return `This sampled normal event from ${alert.sourceIp} to ${alert.destinationIp} was retained for expert validation. The model classified it as ${primaryPrediction} with ${confidence}% confidence.`;
    }

    if (verbosity === "detailed") {
      return `This sampled traffic was classified as normal and retained so analysts can verify that the model is not over-alerting. The model reported ${primaryPrediction} at ${confidence}% confidence. The strongest visible indicators were ${featureSummary}. No containment action was taken, which is expected for strong-normal samples.`;
    }

    return [
      `FORENSIC ANALYSIS - Normal Sample`,
      ``,
      `Traffic Vector: ${alert.sourceIp}:${alert.port || "unknown"} to ${alert.destinationIp} via ${alert.protocol || "unknown"}`,
      ``,
      `Classification Posture: Normal sample retained for validation. Primary class=${primaryPrediction} (${confidence}%)`,
      ``,
      `Key Indicators Observed: ${featureSummary}`,
      ``,
      `Analyst Goal: Confirm the model is correctly preserving benign traffic as non-malicious and monitor for any drift over time.`,
    ].join("\n");
  }

  if (verbosity === "brief") {
    return `This ${alert.threatType} event from ${alert.sourceIp} targeted ${alert.destinationIp}. The model and supporting indicators pointed to malicious behavior, with key evidence including ${featureSummary}. ${blockLine}`;
  }

  if (verbosity === "detailed") {
    return `This alert represents a ${alert.threatType} event originating from ${alert.sourceIp} and targeting ${alert.destinationIp}. The model's primary prediction was ${primaryPrediction} at ${confidence}% confidence. The most relevant indicators were ${featureSummary}. ${blockLine} Review surrounding logs, confirm the attack scope, and maintain the block if the source remains malicious.`;
  }

  return [
    `FORENSIC ANALYSIS - ${alert.threatType}`,
    ``,
    `Attack Vector: Traffic from ${alert.sourceIp}:${alert.port || "unknown"} to ${alert.destinationIp} via ${alert.protocol || "unknown"}`,
    ``,
    `Classification Posture: Confirmed malicious event. Primary class=${primaryPrediction} (${confidence}%)`,
    ``,
    `Key Indicators Detected: ${featureSummary}`,
    ``,
    `Containment Status: ${blockLine}`,
    ``,
    `Immediate Actions Required:`,
    `1. Preserve relevant packet captures and host logs.`,
    `2. Confirm the protected service state and any lateral movement indicators.`,
    `3. Keep the source blocked until the investigation is complete.`,
  ].join("\n");
}

export const threatsRouter = router({

  getAlerts: publicProcedure
    .input(
      z.object({
        limit: z.number().int().default(50),
        offset: z.number().int().default(0),
      })
    )
    .query(async ({ input }) => {
      return getAlerts(input.limit, input.offset);
    }),

  getAlertById: publicProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      return getAlertById(input.id);
    }),

  getAlertsBySeverity: publicProcedure
    .input(
      z.object({
        severity: z.enum(["critical", "high", "medium", "low"]),
        limit: z.number().default(50),
      })
    )
    .query(async ({ input }) => {
      return getAlertsBySeverity(input.severity, input.limit);
    }),

  listExplainable: publicProcedure.query(async () => {
    return getExplainableThreats();
  }),

  blockIp: publicProcedure
    .input(
      z.object({
        ipAddress: z.string(),
        reason: z.string().optional(),
        blockedBy: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const existing = await isIpBlocked(input.ipAddress);

      if (existing)
        return { success: false, message: "IP already blocked" };

      const enforcement = await enforceEdgeBlock(input.ipAddress, input.reason);
      if (!enforcement.success) {
        return {
          success: false,
          message: enforcement.message,
          mode: enforcement.mode,
        };
      }

      await blockIp(input);
      await markAlertsBlockedBySource(input.ipAddress);

      return {
        success: true,
        message: `${input.ipAddress} blocked`,
        mode: enforcement.mode,
      };

    }),

  getBlockedIps: publicProcedure.query(async () => {
    return getBlockedIps();
  }),

  unblockIp: publicProcedure
    .input(z.object({ ipAddress: z.string() }))
    .mutation(async ({ input }) => {
      const enforcement = await enforceEdgeUnblock(
        input.ipAddress,
        "Unblocked from ELAI dashboard",
      );

      if (!enforcement.success) {
        return {
          success: false,
          message: enforcement.message,
          mode: enforcement.mode,
        };
      }

      await unblockIp(input.ipAddress);
      await markAlertsUnblockedBySource(input.ipAddress);

      return {
        success: true,
        message: `${input.ipAddress} unblocked`,
        mode: enforcement.mode,
      };

    }),

  getLatestMetrics: publicProcedure.query(async () => {
    return getLatestSystemMetric();
  }),

  getMetricsHistory: publicProcedure
    .input(z.object({ limit: z.number().default(100) }))
    .query(async ({ input }) => {
      return getSystemMetricsHistory(input.limit);
    }),

  acknowledgeAlert: publicProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {

      await updateAlert(input.id, {
        acknowledged: true,
      } as any);

      return { success: true };

    }),

  blockAlertSource: publicProcedure
    .input(z.object({ alertId: z.number() }))
    .mutation(async ({ input }) => {

      const alert = await getAlertById(input.alertId);

      if (!alert)
        return { success: false, message: "Alert not found" };

      const existing = await isIpBlocked(alert.sourceIp);
      if (existing) {
        await updateAlert(alert.id, { isBlocked: 1 } as any);
        return {
          success: false,
          message: `${alert.sourceIp} is already blocked`,
          mode: getEdgeBlockMode(),
        };
      }

      const enforcement = await enforceEdgeBlock(
        alert.sourceIp,
        `Blocked from alert #${alert.id} (${alert.threatType})`,
      );

      if (!enforcement.success) {
        return {
          success: false,
          message: enforcement.message,
          mode: enforcement.mode,
        };
      }

      await blockIp({
        ipAddress: alert.sourceIp,
        reason: "Blocked via alert",
        blockedBy: "SOC",
      });
      await markAlertsBlockedBySource(alert.sourceIp);
      await updateAlert(alert.id, { isBlocked: 1 } as any);

      return {
        success: true,
        message: `${alert.sourceIp} blocked`,
        mode: enforcement.mode,
      };

    }),

  getAlertCount: publicProcedure.query(async () => {
    return {
      count: await getAlertCount(),
    };
  }),

  clearAlerts: publicProcedure.mutation(async () => {
    await clearAlerts();

    return {
      success: true,
      message: "Alerts cleared",
    };
  }),

  exportAlerts: publicProcedure
    .input(
      z.object({
        format: z.enum(["csv", "pdf"]).default("csv"),
        severity: z.string().optional(),
        limit: z.number().default(1000),
      })
    )
    .mutation(async ({ input }) => {

      const alerts = input.severity
        ? await getAlertsBySeverity(input.severity as any, input.limit)
        : await getAlerts(input.limit, 0);

      const generatedAt = new Date();
      const baseName = `elai-alerts-${generatedAt.toISOString().slice(0, 19).replace(/[:T]/g, "-")}`;

      const fileContent = input.format === "csv"
        ? buildAlertsCsv(alerts as any)
        : buildAlertsPdf(alerts as any);

      return {
        exportDate: generatedAt,
        totalAlerts: alerts.length,
        alerts,
        fileName: `${baseName}.${input.format}`,
        mimeType: input.format === "csv" ? "text/csv;charset=utf-8" : "application/pdf",
        content: fileContent,
      };

    }),

  deepAnalyzeAlert: publicProcedure
    .input(
      z.object({
        id: z.number(),
        verbosity: z.enum(["brief", "detailed", "forensic"]).default("detailed"),
      })
    )
    .mutation(async ({ input }) => {
      const alert = await getAlertById(input.id);

      if (!alert) {
        return { success: false, message: "Alert not found", analysis: "", verbosity: input.verbosity };
      }

      try {
        const features = extractExplanationFeatures(alert.shapeExplanation);

        let analysis = "";

        try {
          analysis = await generateDeepAnalysisWithPython(
            alert.threatType,
            alert.sourceIp,
            features,
            input.verbosity,
          );
        } catch (error) {
          console.warn("[Deep Analysis] Python generation failed, falling back to local summary", error);
          analysis = buildFallbackAnalysis(alert, features, input.verbosity);
        }

        // Update alert with new deep analysis
        await updateAlert(alert.id, {
          deepAnalysis: analysis,
          deepAnalysisVerbosity: input.verbosity,
        } as any);

        return {
          success: true,
          message: "Analysis generated",
          analysis,
          verbosity: input.verbosity,
        };
      } catch (error) {
        return {
          success: false,
          message: `Analysis failed: ${error instanceof Error ? error.message : "Unknown error"}`,
          analysis: "",
          verbosity: input.verbosity,
        };
      }
    }),

});

export const getThreats = () => {
  return getExplainableThreats();
};
