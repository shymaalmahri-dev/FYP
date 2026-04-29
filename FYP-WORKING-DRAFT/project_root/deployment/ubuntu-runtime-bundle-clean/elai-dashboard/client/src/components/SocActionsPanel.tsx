import React, { useState } from "react";
import { Shield, Download, Lock, AlertCircle } from "lucide-react";
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
  blockedIpsCount?: number;
  totalAlerts?: number;
  criticalAlerts?: number;
  onExportPDF?: () => void;
  onExportCSV?: () => void;
  onBlockIp?: (ip: string) => void;
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
  blockedIpsCount = 0,
  totalAlerts = 0,
  criticalAlerts = 0,
  onExportPDF,
  onExportCSV,
  onBlockIp,
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
      onBlockIp?.(blockIpInput.trim());
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
            Add an IP to the blocklist to prevent future connections
          </p>
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
                    <p className="text-sm text-foreground/70">
                      {blockedIpsCount} IP addresses are currently blocked
                    </p>
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
