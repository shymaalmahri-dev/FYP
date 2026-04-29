import React from "react";
import { Activity, Eye, EyeOff, ShieldCheck, TriangleAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface AlertLike {
  id: number;
  timestamp: Date;
  eventCategory?: string | null;
  threatType: string;
  sourceIp: string;
  destinationIp: string;
  protocol?: string | null;
  port?: number | null;
  primaryPrediction?: string | null;
  secondaryPrediction?: string | null;
  modelConfidence?: string | null;
  confidenceGap?: string | null;
  recommendedAction?: string | null;
  blockStatus?: string | null;
}

interface TrafficInsightsPanelProps {
  alerts: AlertLike[];
  showExpertMode: boolean;
  onToggleExpertMode: () => void;
}

const PROTOCOL_LABELS: Record<string, string> = {
  "1": "ICMP",
  "6": "TCP",
  "17": "UDP",
  ICMP: "ICMP",
  TCP: "TCP",
  UDP: "UDP",
};

const COMMON_PORTS: Record<number, string> = {
  22: "SSH",
  53: "DNS",
  80: "HTTP",
  443: "HTTPS",
  8080: "HTTP-Alt",
};

function formatProtocol(protocol?: string | null) {
  if (!protocol) return "unknown";
  return PROTOCOL_LABELS[String(protocol)] || String(protocol);
}

function formatPort(port: number) {
  return COMMON_PORTS[port] ? `${port} (${COMMON_PORTS[port]})` : String(port);
}

function countBy<T extends string | number>(items: T[]) {
  const buckets = new Map<T, number>();
  for (const item of items) {
    buckets.set(item, (buckets.get(item) ?? 0) + 1);
  }
  return Array.from(buckets.entries()).sort((a, b) => b[1] - a[1]);
}

export function TrafficInsightsPanel({
  alerts,
  showExpertMode,
  onToggleExpertMode,
}: TrafficInsightsPanelProps) {
  const malicious = alerts.filter(alert => (alert.eventCategory ?? "malicious") === "malicious");
  const grayZone = alerts.filter(alert => alert.eventCategory === "gray_zone");
  const normal = alerts.filter(alert => alert.eventCategory === "normal");
  const blocked = alerts.filter(alert => alert.blockStatus === "blocked");
  const failedBlocks = alerts.filter(alert => alert.blockStatus === "failed");

  const topProtocols = countBy(
    alerts.map(alert => formatProtocol(alert.protocol))
  ).slice(0, 4);
  const topPorts = countBy(
    alerts
      .map(alert => (alert.port ?? 0))
      .filter(port => port > 0)
  ).slice(0, 4);

  return (
    <Card
      className="border-cyan-600 bg-cyan-950/10"
      style={{ boxShadow: "0 0 15px rgba(34, 211, 238, 0.4), 0 0 30px rgba(34, 211, 238, 0.2)" }}
    >
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle className="flex items-center gap-2 text-cyan-400">
            <Activity className="w-5 h-5" />
            Traffic Insights
          </CardTitle>
          <Button size="sm" variant="outline" onClick={onToggleExpertMode}>
            {showExpertMode ? (
              <>
                <EyeOff className="mr-2 h-4 w-4" />
                Hide Expert View
              </>
            ) : (
              <>
                <Eye className="mr-2 h-4 w-4" />
                Expert View
              </>
            )}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <div className="rounded border border-cyan-700/20 bg-background p-3">
            <div className="text-xs text-foreground/60">Total Events</div>
            <div className="mt-1 text-2xl font-bold text-cyan-400">{alerts.length}</div>
          </div>
          <div className="rounded border border-red-700/20 bg-background p-3">
            <div className="text-xs text-foreground/60">Malicious</div>
            <div className="mt-1 text-2xl font-bold text-red-400">{malicious.length}</div>
          </div>
          <div className="rounded border border-yellow-700/20 bg-background p-3">
            <div className="text-xs text-foreground/60">Gray Zone</div>
            <div className="mt-1 text-2xl font-bold text-yellow-300">{grayZone.length}</div>
          </div>
          <div className="rounded border border-green-700/20 bg-background p-3">
            <div className="text-xs text-foreground/60">Normal Samples</div>
            <div className="mt-1 text-2xl font-bold text-green-400">{normal.length}</div>
          </div>
          <div className="rounded border border-cyan-700/20 bg-background p-3">
            <div className="text-xs text-foreground/60">Blocked</div>
            <div className="mt-1 text-2xl font-bold text-cyan-300">{blocked.length}</div>
            {failedBlocks.length > 0 && (
              <div className="mt-1 text-xs text-red-300">Failed: {failedBlocks.length}</div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded border border-cyan-700/20 bg-background p-4">
            <div className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300/75">
              Top Protocols
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {topProtocols.length === 0 ? (
                <span className="text-sm text-foreground/50">No protocol telemetry yet</span>
              ) : (
                topProtocols.map(([protocol, count]) => (
                  <Badge key={String(protocol)} className="bg-cyan-950 text-cyan-300 border border-cyan-700/20">
                    {protocol}: {count}
                  </Badge>
                ))
              )}
            </div>
          </div>

          <div className="rounded border border-cyan-700/20 bg-background p-4">
            <div className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300/75">
              Top Ports
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {topPorts.length === 0 ? (
                <span className="text-sm text-foreground/50">No port telemetry yet</span>
              ) : (
                topPorts.map(([port, count]) => (
                  <Badge key={String(port)} className="bg-cyan-950 text-cyan-300 border border-cyan-700/20">
                    {port}: {count}
                  </Badge>
                ))
              )}
            </div>
          </div>
        </div>

        {showExpertMode && (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded border border-yellow-700/20 bg-yellow-950/10 p-4">
              <div className="flex items-center gap-2 text-yellow-300">
                <TriangleAlert className="h-4 w-4" />
                <span className="text-xs font-semibold uppercase tracking-[0.16em]">Gray Zone Review Queue</span>
              </div>
              <div className="mt-3 space-y-2 max-h-64 overflow-y-auto">
                {grayZone.length === 0 ? (
                  <p className="text-sm text-foreground/50">No gray-zone events in the current window.</p>
                ) : (
                  grayZone.slice(0, 10).map((event) => (
                    <div key={event.id} className="rounded border border-yellow-700/20 bg-background p-3">
                      <p className="text-sm font-medium text-foreground">{event.primaryPrediction || event.threatType}</p>
                      <p className="mt-1 text-xs text-foreground/60">
                        {event.sourceIp} {"->"} {event.destinationIp}
                      </p>
                      <p className="mt-1 text-xs text-yellow-200">
                        Confidence {event.modelConfidence ?? "0"}% | Gap {event.confidenceGap ?? "0"}%
                      </p>
                      <p className="mt-1 text-xs text-foreground/60">
                        Protocol {formatProtocol(event.protocol)} | Port {event.port ? formatPort(event.port) : "unknown"}
                      </p>
                      <p className="mt-1 text-xs text-foreground/60">
                        {event.recommendedAction || "Review before containment"}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="rounded border border-green-700/20 bg-green-950/10 p-4">
              <div className="flex items-center gap-2 text-green-300">
                <ShieldCheck className="h-4 w-4" />
                <span className="text-xs font-semibold uppercase tracking-[0.16em]">Normal Traffic Samples</span>
              </div>
              <div className="mt-3 space-y-2 max-h-64 overflow-y-auto">
                {normal.length === 0 ? (
                  <p className="text-sm text-foreground/50">No sampled normal traffic yet.</p>
                ) : (
                  normal.slice(0, 10).map((event) => (
                    <div key={event.id} className="rounded border border-green-700/20 bg-background p-3">
                      <p className="text-sm font-medium text-foreground">{event.threatType}</p>
                      <p className="mt-1 text-xs text-foreground/60">
                        {event.sourceIp} {"->"} {event.destinationIp}
                      </p>
                      <p className="mt-1 text-xs text-green-200">
                        Normal confidence {event.modelConfidence ?? "0"}%
                      </p>
                      <p className="mt-1 text-xs text-foreground/60">
                        Protocol {formatProtocol(event.protocol)} | Port {event.port ? formatPort(event.port) : "unknown"}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
