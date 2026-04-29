import React, { useState } from "react";
import { ChevronLeft, ChevronRight, Download, Filter } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface Alert {
  id: number;
  timestamp: Date;
  severity: "critical" | "high" | "medium" | "low";
  threatType: string;
  sourceIp: string;
  destinationIp: string;
  protocol?: string | null;
  port?: number | null;
  modelConfidence?: string | null;
  isBlocked: number;
}


interface AlertsTableProps {
  alerts: Alert[];
  isLoading?: boolean;
  onExport?: () => void;
  selectedAlertId?: number | null;
  onSelectAlert?: (alert: Alert) => void;
}

export function AlertsTable({ alerts, isLoading = false, onExport, selectedAlertId, onSelectAlert }: AlertsTableProps) {
  const [currentPage, setCurrentPage] = useState(1);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"timestamp" | "severity">("timestamp");
  const itemsPerPage = 10;

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: "bg-red-600 text-white",
      high: "bg-orange-600 text-white",
      medium: "bg-yellow-600 text-black",
      low: "bg-cyan-600 text-white",
    };
    return colors[severity] || colors.low;
  };

  const filteredAlerts = alerts.filter(
    (alert) => severityFilter === "all" || alert.severity === severityFilter
  );

  const sortedAlerts = [...filteredAlerts].sort((a, b) => {
    if (sortBy === "timestamp") {
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    } else {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    }
  });

  const totalPages = Math.ceil(sortedAlerts.length / itemsPerPage);
  const startIdx = (currentPage - 1) * itemsPerPage;
  const paginatedAlerts = sortedAlerts.slice(startIdx, startIdx + itemsPerPage);

  const formatTime = (date: Date) => {
    const d = new Date(date);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  if (isLoading) {
    return (
      <Card className="border-cyan-600 bg-cyan-950/10" style={{ boxShadow: "0 0 15px rgba(34, 211, 238, 0.4), 0 0 30px rgba(34, 211, 238, 0.2)" }}>
        <CardHeader>
          <CardTitle className="text-cyan-400">Historical Alerts</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 animate-pulse">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-12 bg-muted rounded" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-cyan-600 bg-cyan-950/10" style={{ boxShadow: "0 0 15px rgba(34, 211, 238, 0.4), 0 0 30px rgba(34, 211, 238, 0.2)" }}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-cyan-400">Historical Alerts</CardTitle>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={onExport}
              className="gap-2"
            >
              <Download className="w-4 h-4" />
              Export
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Filters */}
        <div className="flex gap-2 items-center flex-wrap">
          <Filter className="w-4 h-4 text-foreground/50" />
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-32 h-8 text-xs">
              <SelectValue placeholder="Filter by severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>

          <Select value={sortBy} onValueChange={(v: "timestamp" | "severity") => setSortBy(v)}>
            <SelectTrigger className="w-32 h-8 text-xs">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="timestamp">Latest First</SelectItem>
              <SelectItem value="severity">By Severity</SelectItem>
            </SelectContent>
          </Select>

          <div className="ml-auto text-xs text-foreground/50">
            {filteredAlerts.length} alerts
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyan-600/30 text-cyan-400">
                <th className="text-left py-2 px-2">Time</th>
                <th className="text-left py-2 px-2">Severity</th>
                <th className="text-left py-2 px-2">Threat Type</th>
                <th className="text-left py-2 px-2">Source (Attacker) IP</th>
                <th className="text-left py-2 px-2">Destination IP</th>
                <th className="text-left py-2 px-2">Port</th>
                <th className="text-left py-2 px-2">Confidence</th>
                <th className="text-left py-2 px-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-foreground/50">
                    No alerts found
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className={`border-b border-cyan-600/10 transition-colors cursor-pointer ${selectedAlertId === alert.id ? 'bg-cyan-950/40 border-cyan-400' : 'hover:bg-cyan-950/20'}`}
                    onClick={() => onSelectAlert && onSelectAlert({ ...alert })}
                  >
                    <td className="py-2 px-2 text-foreground/70 text-xs">
                      {formatTime(alert.timestamp)}
                    </td>
                    <td className="py-2 px-2">
                      <Badge className={getSeverityColor(alert.severity)}>
                        {alert.severity.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="py-2 px-2 text-foreground/80 truncate max-w-xs">
                      {alert.threatType}
                    </td>
                    <td className="py-2 px-2 font-mono text-cyan-300 text-xs">
                      {alert.sourceIp}
                    </td>
                    <td className="py-2 px-2 font-mono text-cyan-300 text-xs">
                      {alert.destinationIp}
                    </td>
                    <td className="py-2 px-2 font-mono text-foreground/70">
                      {alert.port ?? "-"}
                    </td>
                    <td className="py-2 px-2">
                      {alert.modelConfidence && (
                        <div className="flex items-center gap-1">
                          <div className="w-12 h-1 bg-background rounded-full overflow-hidden">
                            <div
                              className="h-full bg-cyan-500"
                              style={{
                                width: `${parseFloat(alert.modelConfidence)}%`,
                              }}
                            />
                          </div>
                          <span className="text-xs text-cyan-400">
                            {alert.modelConfidence}%
                          </span>
                        </div>
                      )}
                    </td>
                    <td className="py-2 px-2">
                      {alert.isBlocked ? (
                        <Badge variant="outline" className="bg-green-950 text-green-300 border-green-600">
                          Blocked
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-yellow-950 text-yellow-300 border-yellow-600">
                          Active
                        </Badge>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between pt-4 border-t border-cyan-600/30">
            <div className="text-xs text-foreground/50">
              Page {currentPage} of {totalPages}
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
              >
                <ChevronLeft className="w-4 h-4" />
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
              >
                <ChevronRight className="w-4 h-4" />
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}