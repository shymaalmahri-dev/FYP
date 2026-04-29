import React from "react";
import { Activity, Cpu, HardDrive, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface SystemMetrics {
  cpuUsage: string;
  memoryUsage: string;
  memoryTotal: string;
  networkLatency: string;
  diskUsage?: string;
  activeConnections?: number;
}

interface SystemHealthPanelProps {
  metrics: SystemMetrics | null;
  isLoading?: boolean;
}

export function SystemHealthPanel({ metrics, isLoading = false }: SystemHealthPanelProps) {
  const getHealthColor = (value: number, threshold1: number = 50, threshold2: number = 80) => {
    if (value >= threshold2) return "text-red-400";
    if (value >= threshold1) return "text-yellow-400";
    return "text-cyan-400";
  };

  const getHealthBg = (value: number, threshold1: number = 50, threshold2: number = 80) => {
    if (value >= threshold2) return "bg-red-950/30 border-red-600";
    if (value >= threshold1) return "bg-yellow-950/30 border-yellow-600";
    return "bg-cyan-950/30 border-cyan-600";
  };

  const MetricCard = ({
    icon: Icon,
    label,
    value,
    unit = "%",
    threshold1 = 50,
    threshold2 = 80,
  }: {
    icon: React.ReactNode;
    label: string;
    value: string | number;
    unit?: string;
    threshold1?: number;
    threshold2?: number;
  }) => {
    const numValue = typeof value === "string" ? parseFloat(value) : value;
    const isNumeric = !isNaN(numValue);

    return (
      <div
        className={`metric-card border-l-4 ${
          isNumeric ? getHealthBg(numValue, threshold1, threshold2) : "bg-cyan-950/30 border-cyan-600"
        }`}
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-foreground/70">{label}</span>
          <div className={`${isNumeric ? getHealthColor(numValue, threshold1, threshold2) : "text-cyan-400"}`}>
            {Icon}
          </div>
        </div>
        <div className="flex items-baseline gap-1">
          <span className={`text-2xl font-bold ${isNumeric ? getHealthColor(numValue, threshold1, threshold2) : "text-cyan-400"}`}>
            {typeof value === "string" ? parseFloat(value).toFixed(1) : value}
          </span>
          <span className="text-sm text-foreground/50">{unit}</span>
        </div>
        {isNumeric && (
          <div className="mt-2 h-1 bg-background rounded-full overflow-hidden">
            <div
              className={`h-full transition-all ${
                numValue >= threshold2
                  ? "bg-red-500"
                  : numValue >= threshold1
                    ? "bg-yellow-500"
                    : "bg-cyan-500"
              }`}
              style={{ width: `${Math.min(numValue, 100)}%` }}
            />
          </div>
        )}
      </div>
    );
  };

  if (isLoading || !metrics) {
    return (
      <Card className="border-cyan-600 bg-cyan-950/10" style={{ boxShadow: "0 0 15px rgba(34, 211, 238, 0.4), 0 0 30px rgba(34, 211, 238, 0.2)" }}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-cyan-400">
            <Activity className="w-5 h-5" />
            System Health
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="metric-card animate-pulse">
                <div className="h-4 bg-muted rounded w-1/2 mb-2" />
                <div className="h-8 bg-muted rounded w-3/4" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-cyan-600 bg-cyan-950/10" style={{ boxShadow: "0 0 15px rgba(34, 211, 238, 0.4), 0 0 30px rgba(34, 211, 238, 0.2)" }}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-cyan-400">
          <Activity className="w-5 h-5" />
          System Health
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            icon={<Cpu className="w-4 h-4" />}
            label="CPU Usage"
            value={metrics.cpuUsage}
            unit="%"
          />
          <MetricCard
            icon={<HardDrive className="w-4 h-4" />}
            label="Memory"
            value={metrics.memoryUsage}
            unit={`% of ${metrics.memoryTotal}`}
          />
          <MetricCard
            icon={<Zap className="w-4 h-4" />}
            label="Network Latency"
            value={metrics.networkLatency}
            unit="ms"
            threshold1={20}
            threshold2={50}
          />
          <MetricCard
            icon={<Activity className="w-4 h-4" />}
            label="Active Connections"
            value={metrics.activeConnections || 0}
            unit="conn"
            threshold1={200}
            threshold2={400}
          />
        </div>
      </CardContent>
    </Card>
  );
}
