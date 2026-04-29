import React, { useState } from "react";
import { Shield, Download, Lock, AlertCircle, Eraser, Eye, EyeOff, FlaskConical, Unlock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface SocActionsPanelProps {
  blockedIps?: Array<{
    ipAddress: string;
    blockedAt?: string | Date;
    reason?: string | null;
    blockedBy?: string | null;
    relatedAlerts?: number;
    lastThreatType?: string | null;
    lastSeverity?: string | null;
    lastSeenAt?: string | Date | null;
    edgeDevice?: string | null;
    statusLabel?: string | null;
  }>;
  blockedIpsCount?: number;
  totalAlerts?: number;
  criticalAlerts?: number;
  onExportPDF?: () => void;
  onExportCSV?: () => void;
  onBlockIp?: (ip: string, alertId?: number) => void;
  onUnblockIp?: (ip: string) => void;
  onClearAlerts?: () => void;
  showCurrentSessionOnly?: boolean;
  onToggleCurrentSessionOnly?: () => void;
  showExpertMode?: boolean;
  onToggleExpertMode?: () => void;
  selectedAlert?: {
    id: number;
    sourceIp: string;
    threatType: string;
    severity: string;
    isBlocked: number;
    blockStatus?: string | null;
    blockMessage?: string | null;
  } | null;
  isLoading?: boolean;
  systemStatus?: {
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
  } | null;
}

export function SocActionsPanel({
  blockedIps = [],
  blockedIpsCount = 0,
  totalAlerts = 0,
  criticalAlerts = 0,
  onExportPDF,
  onExportCSV,
  onBlockIp,
  onUnblockIp,
  onClearAlerts,
  showCurrentSessionOnly = true,
  onToggleCurrentSessionOnly,
  showExpertMode = false,
  onToggleExpertMode,
  selectedAlert,
  isLoading = false,
  systemStatus,
}: SocActionsPanelProps) {
  const [blockIpInput, setBlockIpInput] = useState("");
  const [exportFormat, setExportFormat] = useState<"pdf" | "csv">("pdf");
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async () => {
    setIsExporting(true);
    try {
      if (exportFormat === "pdf") {
        onExportPDF?.();
      } else {
        onExportCSV?.();
      }
    } finally {
      setIsExporting(false);
    }
  };

  const handleBlockIp = () => {
    if (blockIpInput.trim()) {
      onBlockIp?.(blockIpInput.trim(), undefined);
      setBlockIpInput("");
    }
  };

  const renderStatusBadge = (ok?: boolean) => (
    <Badge className={ok ? "bg-green-600 text-white" : "bg-yellow-700 text-white"}>
      {ok ? "Ready" : "Attention"}
    </Badge>
  );

  return (
    <Card className="border-cyan-600 bg-cyan-950/10" style={{ boxShadow: "0 0 15px rgba(34, 211, 238, 0.4), 0 0 30px rgba(34, 211, 238, 0.2)" }}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-cyan-400">
          <Shield className="w-5 h-5" />
          SOC Actions
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="p-3 bg-background rounded border border-cyan-600/30">
            <div className="text-xs text-foreground/70 mb-1">Blocked IPs</div>
            <div className="text-2xl font-bold text-cyan-400">{blockedIpsCount}</div>
          </div>
          <div className="p-3 bg-background rounded border border-cyan-600/30">
            <div className="text-xs text-foreground/70 mb-1">Total Alerts</div>
            <div className="text-2xl font-bold text-cyan-400">{totalAlerts}</div>
          </div>
          <div className="p-3 bg-background rounded border border-red-600/30">
            <div className="text-xs text-foreground/70 mb-1">Critical</div>
            <div className="text-2xl font-bold text-red-400">{criticalAlerts}</div>
          </div>
        </div>

        {/* Block IP Section */}
        <div className="space-y-2 p-3 bg-background rounded border border-cyan-600/30">
          <div className="flex items-center gap-2 mb-2">
            <Lock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-foreground">Block IP Address</h3>
          </div>
          {selectedAlert && (
            <div className="rounded border border-red-600/30 bg-red-950/10 p-3 space-y-2">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-wide text-red-300">
                    Selected Alert Source
                  </p>
                  <p className="font-mono text-sm text-cyan-300">
                    {selectedAlert.sourceIp}
                  </p>
                  <p className="text-xs text-foreground/60">
                    {selectedAlert.threatType} | {selectedAlert.severity}
                  </p>
                </div>
                <Button
                  size="sm"
                  onClick={() => onBlockIp?.(selectedAlert.sourceIp, selectedAlert.id)}
                  disabled={isLoading || !!selectedAlert.isBlocked}
                  className="btn-cyber-danger"
                >
                  {selectedAlert.isBlocked ? "Already Blocked" : "Block Selected Source"}
                </Button>
              </div>
              <p className="text-xs text-foreground/50">
                Primary workflow: select an alert, then block its attacker IP from here.
              </p>
              {selectedAlert.blockStatus && selectedAlert.blockStatus !== "not_requested" && (
                <p className="text-xs text-cyan-200">
                  Status: {selectedAlert.blockStatus.replace("_", " ")}
                  {selectedAlert.blockMessage ? ` | ${selectedAlert.blockMessage}` : ""}
                </p>
              )}
            </div>
          )}
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Enter IP address (e.g., 192.168.1.100)"
              value={blockIpInput}
              onChange={(e) => setBlockIpInput(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleBlockIp()}
              className="flex-1 px-3 py-2 text-sm bg-background border border-cyan-600/50 rounded text-foreground placeholder-foreground/40 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
            />
            <Button
              size="sm"
              onClick={handleBlockIp}
              disabled={!blockIpInput.trim() || isLoading}
              className="btn-cyber-danger"
            >
              Block
            </Button>
          </div>
          <p className="text-xs text-foreground/50">
            Manual entry is kept as a fallback for known IPs outside the current alert list.
          </p>
        </div>

        <div className="space-y-3 p-3 bg-background rounded border border-cyan-600/30">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-foreground">Active Blocked IPs</h3>
            </div>
            <Badge className="bg-cyan-950 text-cyan-300 border border-cyan-700/20">
              {blockedIpsCount}
            </Badge>
          </div>

          {blockedIpsCount === 0 ? (
            <p className="text-xs text-foreground/50">
              No blocked IPs are active right now.
            </p>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {blockedIps.slice(0, 6).map((entry) => (
                <div
                  key={entry.ipAddress}
                  className="rounded border border-cyan-700/20 bg-cyan-950/10 p-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-mono text-sm text-cyan-300">{entry.ipAddress}</p>
                      <p className="mt-1 text-xs text-foreground/60">
                        {entry.reason || "Blocked by ELAI response logic"}
                      </p>
                      <div className="mt-2 flex flex-wrap gap-2 text-[11px]">
                        {entry.statusLabel && (
                          <Badge variant="outline" className="bg-green-950 text-green-300 border-green-700/20">
                            {entry.statusLabel}
                          </Badge>
                        )}
                        {typeof entry.relatedAlerts === "number" && (
                          <Badge variant="outline" className="bg-cyan-950 text-cyan-300 border-cyan-700/20">
                            {entry.relatedAlerts} related alerts
                          </Badge>
                        )}
                        {entry.lastThreatType && (
                          <Badge variant="outline" className="bg-red-950 text-red-300 border-red-700/20">
                            Last threat: {entry.lastThreatType}
                          </Badge>
                        )}
                      </div>
                      <p className="mt-1 text-xs text-foreground/50">
                        {entry.blockedAt
                          ? `Blocked at ${new Date(entry.blockedAt).toLocaleString()}`
                          : "Blocked time unavailable"}
                      </p>
                      <p className="mt-1 text-xs text-foreground/50">
                        {entry.lastSeenAt
                          ? `Last seen in alerts ${new Date(entry.lastSeenAt).toLocaleString()}`
                          : "Last related alert time unavailable"}
                      </p>
                      <p className="mt-1 text-xs text-foreground/50">
                        {entry.edgeDevice
                          ? `Edge device: ${entry.edgeDevice}`
                          : entry.blockedBy
                            ? `Blocked by: ${entry.blockedBy}`
                            : "Blocking source unavailable"}
                      </p>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs"
                      onClick={() => onUnblockIp?.(entry.ipAddress)}
                    >
                      <Unlock className="mr-2 h-4 w-4" />
                      Unblock
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Export Section */}
        <div className="space-y-2 p-3 bg-background rounded border border-cyan-600/30">
          <div className="flex items-center gap-2 mb-2">
            <Download className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-foreground">Export Report</h3>
          </div>
          <div className="flex gap-2">
            <Select value={exportFormat} onValueChange={(v) => setExportFormat(v as any)}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="pdf">PDF Report</SelectItem>
                <SelectItem value="csv">CSV Data</SelectItem>
              </SelectContent>
            </Select>
            <Button
              size="sm"
              onClick={handleExport}
              disabled={isLoading || isExporting}
              className="btn-cyber-primary"
            >
              {isExporting ? "Exporting..." : "Export"}
            </Button>
          </div>
          <p className="text-xs text-foreground/50">
            Generate a report of all alerts and security events
          </p>
        </div>

        {/* Quick Actions */}
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-foreground">Quick Actions</h3>
          <div className="grid grid-cols-2 gap-2">
            <Button
              variant="outline"
              size="sm"
              className="text-xs justify-start"
              onClick={onToggleCurrentSessionOnly}
            >
              {showCurrentSessionOnly ? (
                <>
                  <Eye className="mr-2 h-4 w-4" />
                  Session Only
                </>
              ) : (
                <>
                  <EyeOff className="mr-2 h-4 w-4" />
                  Show History
                </>
              )}
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="text-xs justify-start"
              onClick={onToggleExpertMode}
            >
              <FlaskConical className="mr-2 h-4 w-4" />
              {showExpertMode ? "Hide Expert" : "Expert View"}
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="text-xs justify-start text-red-300 border-red-600/40 hover:text-red-200 hover:bg-red-950/30"
              onClick={onClearAlerts}
              disabled={isLoading}
            >
              <Eraser className="mr-2 h-4 w-4" />
              Clear Alerts
            </Button>

            <Dialog>
              <DialogTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-xs"
                >
                  View Blocked IPs
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Blocked IP Addresses</DialogTitle>
                  <DialogDescription>
                    Currently blocked IP addresses in the system
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {blockedIpsCount === 0 ? (
                    <p className="text-sm text-foreground/50 py-4">No blocked IPs</p>
                  ) : (
                    blockedIps.map((entry) => (
                      <div
                        key={entry.ipAddress}
                        className="rounded border border-cyan-700/20 bg-background p-3"
                      >
                        <p className="font-mono text-sm text-cyan-300">{entry.ipAddress}</p>
                        <p className="mt-1 text-xs text-foreground/60">
                          {entry.reason || "Blocked by SOC action"}
                        </p>
                        <div className="mt-2 flex flex-wrap gap-2 text-[11px]">
                          {entry.statusLabel && (
                            <Badge variant="outline" className="bg-green-950 text-green-300 border-green-700/20">
                              {entry.statusLabel}
                            </Badge>
                          )}
                          {typeof entry.relatedAlerts === "number" && (
                            <Badge variant="outline" className="bg-cyan-950 text-cyan-300 border-cyan-700/20">
                              {entry.relatedAlerts} related alerts
                            </Badge>
                          )}
                          {entry.lastThreatType && (
                            <Badge variant="outline" className="bg-red-950 text-red-300 border-red-700/20">
                              Last threat: {entry.lastThreatType}
                            </Badge>
                          )}
                        </div>
                        <p className="mt-1 text-xs text-foreground/50">
                          {entry.blockedAt
                            ? `Blocked at ${new Date(entry.blockedAt).toLocaleString()}`
                            : "Blocked time unavailable"}
                        </p>
                        <p className="mt-1 text-xs text-foreground/50">
                          {entry.lastSeenAt
                            ? `Last seen in alerts ${new Date(entry.lastSeenAt).toLocaleString()}`
                            : "Last related alert time unavailable"}
                        </p>
                        <p className="mt-1 text-xs text-foreground/50">
                          {entry.edgeDevice
                            ? `Edge device: ${entry.edgeDevice}`
                            : entry.blockedBy
                              ? `Blocked by: ${entry.blockedBy}`
                              : "Blocking source unavailable"}
                        </p>
                        <Button
                          size="sm"
                          variant="outline"
                          className="mt-3 text-xs"
                          onClick={() => onUnblockIp?.(entry.ipAddress)}
                        >
                          <Unlock className="mr-2 h-4 w-4" />
                          Unblock
                        </Button>
                      </div>
                    ))
                  )}
                </div>
              </DialogContent>
            </Dialog>

            <Dialog>
              <DialogTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-xs"
                >
                  System Status
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>System Status</DialogTitle>
                  <DialogDescription>
                    Current security and system information
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-2 bg-background rounded">
                    <span className="text-sm">Detection Engine</span>
                    {renderStatusBadge(systemStatus?.services?.detectionEngine?.ok)}
                  </div>
                  <div className="flex items-center justify-between p-2 bg-background rounded">
                    <span className="text-sm">Database</span>
                    {renderStatusBadge(systemStatus?.services?.database?.ok)}
                  </div>
                  <div className="flex items-center justify-between p-2 bg-background rounded">
                    <span className="text-sm">LLM Service</span>
                    {renderStatusBadge(systemStatus?.services?.ollama?.ok)}
                  </div>
                  <div className="flex items-center justify-between p-2 bg-background rounded">
                    <span className="text-sm">WebSocket</span>
                    {renderStatusBadge(systemStatus?.services?.websocket?.ok)}
                  </div>
                  <div className="rounded bg-background p-3 text-xs text-foreground/70 space-y-2">
                    <p>Ingestion mode: {systemStatus?.runtime?.ingestionMode ?? "unknown"}</p>
                    <p>Ollama model: {systemStatus?.runtime?.ollamaModel ?? "unknown"}</p>
                    <p>Database: {systemStatus?.services?.database?.message ?? "Unknown"}</p>
                    <p>LLM: {systemStatus?.services?.ollama?.message ?? "Unknown"}</p>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Alert Info */}
        <div className="p-3 bg-yellow-950/30 border border-yellow-600/30 rounded flex gap-2">
          <AlertCircle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div className="text-xs text-yellow-200">
            <p className="font-semibold mb-1">Security Notice</p>
            <p>All blocked IPs are logged and monitored. Review blocked IPs regularly.</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
