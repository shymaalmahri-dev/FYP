import React, { useState, useEffect } from "react";
import { AlertTriangle, Shield, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

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
}

interface ThreatFeedProps {
  alerts: Alert[];
  isLoading?: boolean;
  onBlockIp?: (ip: string, alertId: number) => void;
}

export function ThreatFeed({ alerts, isLoading = false, onBlockIp }: ThreatFeedProps) {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "threat-critical";
      case "high":
        return "threat-high";
      case "medium":
        return "threat-medium";
      case "low":
        return "threat-low";
      default:
        return "threat-low";
    }
  };

  const getSeverityBadge = (severity: string) => {
    const colors: Record<string, string> = {
      critical: "bg-red-600 text-white",
      high: "bg-orange-600 text-white",
      medium: "bg-yellow-600 text-black",
      low: "bg-cyan-600 text-white",
    };
    return colors[severity] || colors.low;
  };

  const formatTime = (date: Date) => {
    const d = new Date(date);
    return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  if (isLoading) {
    return (
      <Card className="border-red-600 bg-red-950/10" style={{ boxShadow: "0 0 15px rgba(239, 68, 68, 0.4), 0 0 30px rgba(239, 68, 68, 0.2)" }}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="w-5 h-5" />
            Live Threat Feed
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="threat-critical p-4 animate-pulse rounded">
                <div className="h-4 bg-muted rounded w-1/2 mb-2" />
                <div className="h-4 bg-muted rounded w-3/4" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-red-600 bg-red-950/10" style={{ boxShadow: "0 0 15px rgba(239, 68, 68, 0.4), 0 0 30px rgba(239, 68, 68, 0.2)" }}>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-2 text-red-400">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 animate-pulse" />
            Live Threat Feed
          </div>
          <Badge variant="outline" className="bg-red-950 text-red-300 border-red-600">
            {alerts.length} Active
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {alerts.length === 0 ? (
            <div className="text-center py-8 text-foreground/50">
              <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No threats detected</p>
            </div>
          ) : (
            alerts.map((alert) => (
              <div key={alert.id} className={`${getSeverityColor(alert.severity)} p-3 rounded border transition-all hover:shadow-lg`}>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2 flex-1">
                    <Zap className="w-4 h-4 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold text-sm truncate">{alert.threatType}</p>
                      <p className="text-xs opacity-75">{formatTime(alert.timestamp)}</p>
                    </div>
                  </div>
                  <Badge className={getSeverityBadge(alert.severity)}>{alert.severity.toUpperCase()}</Badge>
                </div>

                <div className="grid grid-cols-2 gap-2 mb-2 text-xs">
                  <div>
                    <span className="opacity-70">Source (Attacker):</span>
                    <p className="font-mono text-cyan-300">{alert.sourceIp}</p>
                  </div>
                  <div>
                    <span className="opacity-70">Destination:</span>
                    <p className="font-mono text-cyan-300">{alert.destinationIp}</p>
                  </div>
                </div>

                {alert.protocol && (
                  <div className="flex gap-2 mb-2 text-xs">
                    <span className="opacity-70">Protocol:</span>
                    <span className="font-mono">{alert.protocol}</span>
                    {alert.port && (
                      <>
                        <span className="opacity-70">Port:</span>
                        <span className="font-mono">{alert.port}</span>
                      </>
                    )}
                  </div>
                )}

                {alert.description && <p className="text-xs opacity-80 mb-2">{alert.description}</p>}

                {alert.modelConfidence && (
                  <div className="mb-2">
                    <div className="flex justify-between text-xs mb-1">
                      <span>Confidence</span>
                      <span className="font-mono">{alert.modelConfidence}%</span>
                    </div>
                    <div className="h-1 bg-background rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-red-500"
                        style={{ width: `${parseFloat(alert.modelConfidence || "0")}%` }}
                      />
                    </div>
                  </div>
                )}

                <div className="flex gap-2 pt-2 border-t border-current/20">
                  {!alert.isBlocked && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs btn-cyber-danger"
                      onClick={() => onBlockIp?.(alert.sourceIp, alert.id)}
                    >
                      Block IP
                    </Button>
                  )}
                  {alert.isBlocked && (
                    <Badge variant="outline" className="bg-green-950 text-green-300 border-green-600">
                      ✓ Blocked
                    </Badge>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  );
}
