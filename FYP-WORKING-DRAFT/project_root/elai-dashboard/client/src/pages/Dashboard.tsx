import React, { useEffect, useState, useRef } from "react";
import { io, Socket } from "socket.io-client";
import { SystemHealthPanel } from "@/components/SystemHealthPanel";
import { ThreatFeed } from "@/components/ThreatFeed";
import { ShapExplanationCard } from "@/components/ShapExplanationCard";
import { AlertsTable } from "@/components/AlertsTable";
import { SocActionsPanel } from "@/components/SocActionsPanel";
import { TrafficInsightsPanel } from "@/components/TrafficInsightsPanel";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Shield } from "lucide-react";

const SOCKET_URL = import.meta.env.VITE_API_URL || (() => {
  if (typeof window === "undefined") {
    return "http://localhost:4000";
  }

  const origin = window.location.origin;
  const port = window.location.port;

  if (port && port !== "5173") {
    return origin;
  }

  return "http://localhost:4000";
})();

interface SystemMetrics {
  cpuUsage: string;
  memoryUsage: string;
  memoryTotal: string;
  networkLatency: string;
  diskUsage?: string;
  activeConnections?: number;
}

interface SystemStatus {
  runtime?: {
    ingestionMode?: string;
    ollamaModel?: string;
  };
  services?: {
    detectionEngine?: { ok: boolean; message: string };
    database?: { ok: boolean; message: string };
    ollama?: { ok: boolean; message: string };
    websocket?: { ok: boolean; message: string };
  };
}

interface Alert {
  id: number;
  timestamp: Date;
  severity: "critical" | "high" | "medium" | "low";
  eventCategory?: string | null;
  threatType: string;
  sourceIp: string;
  destinationIp: string;
  protocol?: string | null;
  port?: number | null;
  description?: string | null;
  modelConfidence?: string | null;
  primaryPrediction?: string | null;
  secondaryPrediction?: string | null;
  primaryConfidence?: string | null;
  secondaryConfidence?: string | null;
  confidenceGap?: string | null;
  recommendedAction?: string | null;
  isBlocked: number;
  blockStatus?: string | null;
  blockMessage?: string | null;
  edgeDevice?: string | null;
  shapeExplanation?: string | null;
  llmExplanation?: string | null;
  deepAnalysis?: string | null;
  deepAnalysisVerbosity?: "brief" | "detailed" | "forensic" | null;
}

interface ShapValues {
  baseValue: number;
  prediction: number;
  features?: Array<{
    name: string;
    importance: number;
    value: string;
  }>;
}

const PROTOCOL_LABELS: Record<string, string> = {
  "1": "ICMP",
  "6": "TCP",
  "17": "UDP",
  ICMP: "ICMP",
  TCP: "TCP",
  UDP: "UDP",
};

const normalizeProtocolLabel = (protocol?: string | null) => {
  if (!protocol) return protocol;
  return PROTOCOL_LABELS[String(protocol)] || protocol;
};

const parseShapeExplanation = (
  raw: string,
  modelConfidence?: string | null
): ShapValues | undefined => {
  try {
    const parsed = JSON.parse(raw);
    const prediction = Math.min(Number(modelConfidence ?? 0) / 100, 1) || 0;

    if (Array.isArray(parsed)) {
      return {
        baseValue: 0.5,
        prediction,
        features: parsed.map((item: any) => ({
          name: item.feature || item.name || "unknown",
          importance: Math.abs(item.impact ?? item.importance ?? 0),
          value: String(item.value ?? ""),
        })),
      };
    }

    if (parsed && typeof parsed === "object") {
      if (Array.isArray(parsed.features)) {
        return {
          baseValue: parsed.baseValue ?? 0.5,
          prediction: parsed.prediction ?? prediction,
          features: parsed.features.map((item: any) => ({
            name: item.name || item.feature || "unknown",
            importance: Math.abs(item.importance ?? item.impact ?? 0),
            value: String(item.value ?? ""),
          })),
        };
      }

      const features = Object.entries(parsed).map(([name, value]) => ({
        name,
        importance: 0,
        value: String(value),
      }));

      return {
        baseValue: 0.5,
        prediction,
        features,
      };
    }
  } catch {
    return undefined;
  }

  return undefined;
};

export default function Dashboard() {
  const utils = trpc.useUtils();
  const socketRef = useRef<Socket | null>(null);
  const sessionStartedAtRef = useRef(Date.now());

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [blockedIpsCount, setBlockedIpsCount] = useState(0);
  const [alertCount, setAlertCount] = useState(0);
  const [isConnected, setIsConnected] = useState(false);
  const [showCurrentSessionOnly, setShowCurrentSessionOnly] = useState(true);
  const [showExpertMode, setShowExpertMode] = useState(false);

  const { data: initialAlerts, isLoading: alertsLoading } =
    trpc.threats.getAlerts.useQuery({
      limit: 50,
      offset: 0,
    });

  const { data: initialMetrics, isLoading: metricsLoading } =
    trpc.threats.getLatestMetrics.useQuery();

  const { data: blockedIps } = trpc.threats.getBlockedIps.useQuery();
  const { data: systemStatus } = trpc.system.status.useQuery();

  const isCurrentSessionAlert = (alert: Alert) =>
    new Date(alert.timestamp).getTime() >= sessionStartedAtRef.current;

  const applyAlertView = (incomingAlerts: Alert[]) =>
    showCurrentSessionOnly
      ? incomingAlerts.filter(isCurrentSessionAlert)
      : incomingAlerts;

  const blockIpMutation = trpc.threats.blockIp.useMutation({
    onSuccess: async (result, variables) => {
      if (!result.success) {
        toast.error(result.message);
        return;
      }

      setAlerts(prev =>
        prev.map(alert =>
          alert.sourceIp === variables.ipAddress
            ? {
                ...alert,
                isBlocked: 1,
                blockStatus: "blocked",
                blockMessage: result.message,
              }
            : alert
        )
      );
      setSelectedAlert(prev =>
        prev && prev.sourceIp === variables.ipAddress
          ? {
              ...prev,
              isBlocked: 1,
              blockStatus: "blocked",
              blockMessage: result.message,
            }
          : prev
      );
      toast.success(`IP blocked successfully via ${result.mode}`);
      await utils.threats.getBlockedIps.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const blockAlertSourceMutation = trpc.threats.blockAlertSource.useMutation({
    onSuccess: async (result, variables) => {
      if (!result.success) {
        toast.error(result.message);
        return;
      }

      const sourceIp =
        alerts.find(alert => alert.id === variables.alertId)?.sourceIp ??
        selectedAlert?.sourceIp;

      setAlerts(prev =>
        prev.map(alert =>
          alert.id === variables.alertId || (sourceIp && alert.sourceIp === sourceIp)
            ? {
                ...alert,
                isBlocked: 1,
                blockStatus: "blocked",
                blockMessage: result.message,
              }
            : alert
        )
      );
      setSelectedAlert(prev => prev ? {
        ...prev,
        isBlocked: 1,
        blockStatus: "blocked",
        blockMessage: result.message,
      } : null);
      toast.success(`Alert source blocked via ${result.mode}`);
      await utils.threats.getBlockedIps.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const unblockIpMutation = trpc.threats.unblockIp.useMutation({
    onSuccess: async (result, variables) => {
      if (!result.success) {
        toast.error(result.message);
        return;
      }

      setAlerts(prev =>
        prev.map(alert =>
          alert.sourceIp === variables.ipAddress
            ? {
                ...alert,
                isBlocked: 0,
                blockStatus: "unblocked",
                blockMessage: result.message,
              }
            : alert
        )
      );
      setSelectedAlert(prev =>
        prev && prev.sourceIp === variables.ipAddress
          ? {
              ...prev,
              isBlocked: 0,
              blockStatus: "unblocked",
              blockMessage: result.message,
            }
          : prev
      );
      toast.success(`IP unblocked via ${result.mode}`);
      await utils.threats.getBlockedIps.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const deepAnalyzeAlertMutation = trpc.threats.deepAnalyzeAlert.useMutation({
    onSuccess: (result) => {
      if (result.success) {
        toast.success("Deep analysis completed");
        setAlerts(prev =>
          prev.map(alert =>
            alert.id === selectedAlert?.id
              ? {
                  ...alert,
                  deepAnalysis: result.analysis,
                  deepAnalysisVerbosity: result.verbosity,
                }
              : alert
          )
        );
        setSelectedAlert(prev => prev ? {
          ...prev,
          deepAnalysis: result.analysis,
          deepAnalysisVerbosity: result.verbosity
        } : null);
      } else {
        toast.error(result.message);
      }
    },
    onError: (err) => toast.error(`Analysis failed: ${err.message}`),
  });

  const exportAlertsMutation = trpc.threats.exportAlerts.useMutation({
    onError: (err) => toast.error(`Export failed: ${err.message}`),
  });

  const clearAlertsMutation = trpc.threats.clearAlerts.useMutation({
    onSuccess: () => {
      setAlerts([]);
      setSelectedAlert(null);
      setAlertCount(0);
      sessionStartedAtRef.current = Date.now();
      toast.success("Alert history cleared");
    },
    onError: (err) => toast.error(`Clear failed: ${err.message}`),
  });

  useEffect(() => {
    const socket = io(SOCKET_URL, {
      transports: ["websocket"],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 2000,
    });

    socketRef.current = socket;

    socket.on("connect", () => {
      setIsConnected(true);
      socket.emit("request-initial-data");
    });

    socket.on("disconnect", () => {
      setIsConnected(false);
    });

    socket.on("initial-data", (data: any) => {
      if (data.alerts) setAlerts(applyAlertView(data.alerts));
      if (data.metrics) setMetrics(data.metrics);
    });

    socket.on("new-alert", (alert: Alert) => {
      setAlerts(prevAlerts => {
        const exists = prevAlerts.find((a) => a.id === alert.id);
        if (exists) return prevAlerts;
        const nextAlerts = [alert, ...prevAlerts].slice(0, 50);
        const viewedAlerts = applyAlertView(nextAlerts);
        setAlertCount(viewedAlerts.length);
        return viewedAlerts;
      });

      setSelectedAlert((prev) => prev ?? alert);

      if (alert.severity === "critical") {
        toast.error(`Critical threat detected: ${alert.threatType}`);
      }

      if (alert.blockStatus === "blocked" || alert.blockStatus === "failed") {
        void utils.threats.getBlockedIps.invalidate();
      }
    });

    socket.on("system-metrics", (m: SystemMetrics) => {
      setMetrics(m);
    });

    return () => {
      socket.disconnect();
    };
  }, [showCurrentSessionOnly]);

  useEffect(() => {
    if (initialAlerts && alerts.length === 0) {
      setAlerts(applyAlertView(initialAlerts));
    }
  }, [initialAlerts, showCurrentSessionOnly]);

  useEffect(() => {
    if (initialMetrics) {
      setMetrics(initialMetrics as SystemMetrics);
    }
  }, [initialMetrics]);

  useEffect(() => {
    if (blockedIps) setBlockedIpsCount(blockedIps.length);
  }, [blockedIps]);

  useEffect(() => {
    setAlertCount(alerts.length);
  }, [alerts]);

  useEffect(() => {
    if (initialAlerts) {
      setAlerts(applyAlertView(initialAlerts));
    }
  }, [showCurrentSessionOnly]);

  useEffect(() => {
    if (!selectedAlert && alerts.length > 0) {
      const critical = alerts.find(
        a => (a.eventCategory ?? "malicious") === "malicious" && a.severity === "critical"
      );
      const firstMalicious = alerts.find(
        a => (a.eventCategory ?? "malicious") === "malicious"
      );
      const firstGray = alerts.find(a => a.eventCategory === "gray_zone");
      setSelectedAlert(critical || firstMalicious || firstGray || alerts[0]);
    }
  }, [alerts]);

  const handleBlockIp = (ip: string, alertId?: number) => {
    if (alertId) {
      blockAlertSourceMutation.mutate({ alertId });
      return;
    }

    blockIpMutation.mutate({
      ipAddress: ip,
      reason: "Blocked via dashboard",
      blockedBy: "SOC"
    });
  };

  const downloadFile = (fileName: string, mimeType: string, content: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  const handleExport = async (format: "pdf" | "csv") => {
    const result = await exportAlertsMutation.mutateAsync({
      format,
      limit: 1000,
    });
    downloadFile(result.fileName, result.mimeType, result.content);
    toast.success(`${format.toUpperCase()} export ready`);
  };

  const handleExportPDF = () => {
    void handleExport("pdf");
  };

  const handleExportCSV = () => {
    void handleExport("csv");
  };

  const handleDeepAnalysis = async (alertId: number, verbosity: "brief" | "detailed" | "forensic") => {
    deepAnalyzeAlertMutation.mutate({
      id: alertId,
      verbosity,
    });
  };

  const handleClearAlerts = () => {
    clearAlertsMutation.mutate();
  };

  const handleUnblockIp = (ip: string) => {
    unblockIpMutation.mutate({ ipAddress: ip });
  };

  const criticalCount = alerts.filter(a => a.severity === "critical").length;
  const maliciousAlerts = alerts.filter(
    (alert) => (alert.eventCategory ?? "malicious") === "malicious"
  );
  const blockedIpTelemetry = new Map<string, {
    relatedAlerts: number;
    lastThreatType: string | null;
    lastSeverity: string | null;
    lastSeenAt: Date | null;
    edgeDevice: string | null;
  }>();

  for (const alert of alerts) {
    const sourceIp = alert.sourceIp;
    if (!sourceIp) continue;

    const current = blockedIpTelemetry.get(sourceIp);
    const alertTime = alert.timestamp ? new Date(alert.timestamp) : null;

    if (!current) {
      blockedIpTelemetry.set(sourceIp, {
        relatedAlerts: 1,
        lastThreatType: alert.threatType ?? null,
        lastSeverity: alert.severity ?? null,
        lastSeenAt: alertTime,
        edgeDevice: alert.edgeDevice ?? null,
      });
      continue;
    }

    current.relatedAlerts += 1;
    if (alertTime && (!current.lastSeenAt || alertTime.getTime() > current.lastSeenAt.getTime())) {
      current.lastSeenAt = alertTime;
      current.lastThreatType = alert.threatType ?? current.lastThreatType;
      current.lastSeverity = alert.severity ?? current.lastSeverity;
      current.edgeDevice = alert.edgeDevice ?? current.edgeDevice;
    }
  }

  const visibleBlockedIps = ((blockedIps as any[] | undefined) ?? []).map((entry) => {
    const telemetry = blockedIpTelemetry.get(entry.ipAddress);
    return {
      ...entry,
      relatedAlerts: telemetry?.relatedAlerts ?? 0,
      lastThreatType: telemetry?.lastThreatType ?? null,
      lastSeverity: telemetry?.lastSeverity ?? null,
      lastSeenAt: telemetry?.lastSeenAt ?? null,
      edgeDevice: telemetry?.edgeDevice ?? null,
      statusLabel: "Firewall Active",
    };
  });
  const visibleBlockedIpsCount = visibleBlockedIps.length;

  return (
    <div className="min-h-screen bg-background text-foreground">

      <header className="border-b border-cyan-600/30 sticky top-0 z-50">
        <div className="container py-4 flex justify-between">

          <div className="flex items-center gap-3">
            <Shield className="text-cyan-400" />
            <h1 className="text-xl font-bold text-cyan-400">
              ELAI Dashboard
            </h1>
          </div>

          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${isConnected ? "bg-green-500" : "bg-red-500"}`} />
            <span className="text-xs">
              {isConnected ? "Connected" : "Disconnected"}
            </span>
          </div>

        </div>
      </header>

      <main className="container py-6 space-y-6">

        <SystemHealthPanel
          metrics={metrics}
          isLoading={metricsLoading}
        />

        <TrafficInsightsPanel
          alerts={alerts}
          showExpertMode={showExpertMode}
          onToggleExpertMode={() => setShowExpertMode((current) => !current)}
        />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          <div className="lg:col-span-2 space-y-6">

            <ThreatFeed
              alerts={maliciousAlerts}
              isLoading={alertsLoading}
              onBlockIp={(ip, alertId) => handleBlockIp(ip, alertId)}
            />

            <AlertsTable
              alerts={alerts}
              isLoading={alertsLoading}
              onExport={handleExportPDF}
              selectedAlertId={selectedAlert?.id ?? null}
              onSelectAlert={setSelectedAlert}
            />

          </div>

          <div className="space-y-6">

            {selectedAlert && (
              <ShapExplanationCard
                threatType={selectedAlert.threatType}
                description={selectedAlert.description}
                sourceIp={selectedAlert.sourceIp}
                destinationIp={selectedAlert.destinationIp}
                protocol={normalizeProtocolLabel(selectedAlert.protocol)}
                port={selectedAlert.port}
                severity={selectedAlert.severity}
                shapValues={
                  selectedAlert.shapeExplanation
                    ? parseShapeExplanation(
                        selectedAlert.shapeExplanation,
                        selectedAlert.modelConfidence
                      )
                    : undefined
                }
                llmExplanation={selectedAlert.llmExplanation || undefined}
                alertId={selectedAlert.id}
                onDeepAnalysis={handleDeepAnalysis}
                deepAnalysis={selectedAlert.deepAnalysis || undefined}
                deepAnalysisVerbosity={selectedAlert.deepAnalysisVerbosity || undefined}
              />
            )}

            <SocActionsPanel
              blockedIps={visibleBlockedIps as any}
              blockedIpsCount={visibleBlockedIpsCount}
              totalAlerts={alertCount}
              criticalAlerts={criticalCount}
              onExportPDF={handleExportPDF}
              onExportCSV={handleExportCSV}
              onBlockIp={handleBlockIp}
              onUnblockIp={handleUnblockIp}
              onClearAlerts={handleClearAlerts}
              showCurrentSessionOnly={showCurrentSessionOnly}
              onToggleCurrentSessionOnly={() =>
                setShowCurrentSessionOnly((current) => !current)
              }
              showExpertMode={showExpertMode}
              onToggleExpertMode={() =>
                setShowExpertMode((current) => !current)
              }
              selectedAlert={selectedAlert ? {
                id: selectedAlert.id,
                sourceIp: selectedAlert.sourceIp,
                threatType: selectedAlert.threatType,
                severity: selectedAlert.severity,
                isBlocked: selectedAlert.isBlocked,
                blockStatus: selectedAlert.blockStatus,
                blockMessage: selectedAlert.blockMessage,
              } : null}
              isLoading={
                blockIpMutation.isPending ||
                blockAlertSourceMutation.isPending ||
                exportAlertsMutation.isPending ||
                clearAlertsMutation.isPending
                || unblockIpMutation.isPending
              }
              systemStatus={systemStatus as SystemStatus | undefined}
            />

          </div>

        </div>

      </main>

    </div>
  );
}
