import React, { useEffect, useState, useRef } from "react";
import { io, Socket } from "socket.io-client";
import { SystemHealthPanel } from "@/components/SystemHealthPanel";
import { ThreatFeed } from "@/components/ThreatFeed";
import { ShapExplanationCard } from "@/components/ShapExplanationCard";
import { AlertsTable } from "@/components/AlertsTable";
import { SocActionsPanel } from "@/components/SocActionsPanel";
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
  threatType: string;
  sourceIp: string;
  destinationIp: string;
  protocol?: string | null;
  port?: number | null;
  description?: string | null;
  modelConfidence?: string | null;
  isBlocked: number;
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

const parseShapeExplanation = (raw: string): ShapValues | undefined => {
  try {
    const parsed = JSON.parse(raw);

    if (Array.isArray(parsed)) {
      return {
        baseValue: 0.5,
        prediction: 0.95,
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
          prediction: parsed.prediction ?? 0.95,
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
        prediction: 0.95,
        features,
      };
    }
  } catch {
    return undefined;
  }

  return undefined;
};

export default function Dashboard() {

  const socketRef = useRef<Socket | null>(null);
  const sessionStartedAtRef = useRef(Date.now());

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [blockedIpsCount, setBlockedIpsCount] = useState(0);
  const [alertCount, setAlertCount] = useState(0);
  const [isConnected, setIsConnected] = useState(false);

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

  const filterSessionAlerts = (incomingAlerts: Alert[]) =>
    incomingAlerts.filter(isCurrentSessionAlert);

  const blockIpMutation = trpc.threats.blockIp.useMutation({
    onSuccess: () => toast.success("IP blocked successfully"),
    onError: (err) => toast.error(err.message),
  });

  const blockAlertSourceMutation = trpc.threats.blockAlertSource.useMutation({
    onSuccess: () => toast.success("Alert source blocked"),
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
      if (data.alerts) setAlerts(filterSessionAlerts(data.alerts));
      if (data.metrics) setMetrics(data.metrics);
    });

    socket.on("new-alert", (alert: Alert) => {
      setAlerts((prev) => {
        const exists = prev.find((a) => a.id === alert.id);
        if (exists) return prev;
        setAlertCount((current) => current + 1);
        return [alert, ...prev].slice(0, 50);
      });

      setSelectedAlert((prev) => prev ?? alert);

      if (alert.severity === "critical") {
        toast.error(`Critical threat detected: ${alert.threatType}`);
      }
    });

    socket.on("system-metrics", (m: SystemMetrics) => {
      setMetrics(m);
    });

    return () => {
      socket.disconnect();
    };

  }, []);

  useEffect(() => {
    if (initialAlerts && alerts.length === 0) {
      setAlerts(filterSessionAlerts(initialAlerts));
    }
  }, [initialAlerts]);

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
    if (!selectedAlert && alerts.length > 0) {
      const critical = alerts.find(a => a.severity === "critical");
      setSelectedAlert(critical || alerts[0]);
    }
  }, [alerts]);

  const handleBlockIp = (ip: string) => {
    blockIpMutation.mutate({
      ipAddress: ip,
      reason: "Blocked via dashboard",
      blockedBy: "SOC"
    });
  };

  const handleBlockAlertSource = (alertId?: number) => {
    if (!alertId) return;
    blockAlertSourceMutation.mutate({ alertId });
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

  const criticalCount = alerts.filter(a => a.severity === "critical").length;

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

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          <div className="lg:col-span-2 space-y-6">

            <ThreatFeed
              alerts={alerts}
              isLoading={alertsLoading}
              onBlockIp={(ip, alertId) => handleBlockAlertSource(alertId)}
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
                protocol={selectedAlert.protocol}
                port={selectedAlert.port}
                severity={selectedAlert.severity}
                shapValues={
                  selectedAlert.shapeExplanation
                    ? parseShapeExplanation(selectedAlert.shapeExplanation)
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
              blockedIpsCount={blockedIpsCount}
              totalAlerts={alertCount}
              criticalAlerts={criticalCount}
              onExportPDF={handleExportPDF}
              onExportCSV={handleExportCSV}
              onBlockIp={handleBlockIp}
              isLoading={blockIpMutation.isPending || exportAlertsMutation.isPending}
              systemStatus={systemStatus as SystemStatus | undefined}
            />

          </div>

        </div>

      </main>

    </div>
  );
}
