import { z } from "zod";
import { router, publicProcedure } from "../_core/trpc";

import {
  getAlerts,
  getAlertById,
  getAlertsBySeverity,
  getAlertCount,
  updateAlert,
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

      await blockIp(input);

      return {
        success: true,
        message: `${input.ipAddress} blocked`,
      };

    }),

  getBlockedIps: publicProcedure.query(async () => {
    return getBlockedIps();
  }),

  unblockIp: publicProcedure
    .input(z.object({ ipAddress: z.string() }))
    .mutation(async ({ input }) => {

      await unblockIp(input.ipAddress);

      return {
        success: true,
        message: `${input.ipAddress} unblocked`,
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

      await blockIp({
        ipAddress: alert.sourceIp,
        reason: "Blocked via alert",
        blockedBy: "SOC",
      });

      return {
        success: true,
        message: `${alert.sourceIp} blocked`,
      };

    }),

  getAlertCount: publicProcedure.query(async () => {
    return {
      count: await getAlertCount(),
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

          if (input.verbosity === "brief") {
            const topFeatures = features.slice(0, 2).map((f: any) => f.feature).join(", ");
            analysis = `This ${alert.threatType} attack from ${alert.sourceIp} was detected based on abnormal patterns including ${topFeatures}. The model flagged this as malicious with high confidence.`;
          } else if (input.verbosity === "detailed") {
            const topFeatures = features.slice(0, 3).map((f: any) => `${f.feature} (impact: ${Math.round((f.impact ?? 0) * 100)}%)`).join(", ");
            analysis = `This alert represents a ${alert.threatType} attack originating from ${alert.sourceIp} targeting ${alert.destinationIp}. The machine learning model identified critical behavioral indicators: ${topFeatures}. `;
            analysis += `These features strongly suggest malicious activity attempting to ${alert.threatType.toLowerCase().replace(/_/g, " ")}. Immediate investigation of this source IP and isolation of the target system is recommended. Review firewall logs and check for any successful lateral movement.`;
          } else {
            const topFeatures = features.slice(0, 5).map((f: any) => `${f.feature} (${Math.round((f.impact ?? 0) * 100)}%)`).join(", ");
            analysis = `FORENSIC ANALYSIS - ${alert.threatType} Attack\n\n`;
            analysis += `Attack Vector: Network packet from ${alert.sourceIp}:${alert.port || "unknown"} to ${alert.destinationIp} via ${alert.protocol || "unknown"}\n\n`;
            analysis += `Key Indicators Detected:\n${topFeatures}\n\n`;
            analysis += `Attacker Objective: Likely attempting to ${alert.threatType.toLowerCase().replace(/_/g, " ")} the target system, potentially for reconnaissance, data exfiltration, or service disruption.\n\n`;
            analysis += `Immediate Actions Required:\n1. Block source IP at firewall/WAF\n2. Isolate target system if critical\n3. Capture network packets for forensic analysis\n4. Review system logs for successful compromise indicators\n5. Check for lateral movement to other systems\n\n`;
            analysis += `Evidence Preservation:\n- Collect network traffic captures\n- Preserve system logs and audit trails\n- Document timeline of related alerts\n- Save system memory image if possible\n\n`;
            analysis += `Long-term Mitigation:\n- Patch identified vulnerabilities\n- Implement additional network segmentation\n- Deploy updated IDS/IPS signatures\n- Enhance monitoring and alerting rules`;
          }
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
