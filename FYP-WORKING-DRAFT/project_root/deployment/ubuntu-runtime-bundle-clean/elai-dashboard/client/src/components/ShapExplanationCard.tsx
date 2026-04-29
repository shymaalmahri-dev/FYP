import React, { useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

import { Brain, TrendingUp, FileText, Loader2 } from "lucide-react";

interface ShapFeature {
  name: string;
  importance: number;
  value: string;
}

interface ShapValues {
  baseValue: number;
  features?: ShapFeature[];
  prediction: number;
}

interface ShapExplanationCardProps {
  threatType?: string;
  shapValues?: ShapValues;
  llmExplanation?: string;
  description?: string | null;
  sourceIp?: string;
  destinationIp?: string;
  protocol?: string | null;
  port?: number | null;
  severity?: string;
  isLoading?: boolean;
  alertId?: number;
  onDeepAnalysis?: (alertId: number, verbosity: "brief" | "detailed" | "forensic") => Promise<void>;
  deepAnalysis?: string;
  deepAnalysisVerbosity?: "brief" | "detailed" | "forensic";
}

export function ShapExplanationCard({
  threatType = "Unknown Threat",
  shapValues,
  llmExplanation,
  description,
  sourceIp,
  destinationIp,
  protocol,
  port,
  severity,
  isLoading = false,
  alertId,
  onDeepAnalysis,
  deepAnalysis,
  deepAnalysisVerbosity,
}: ShapExplanationCardProps) {

  const features = shapValues?.features ?? [];

  const chartData = features
    .map((feature) => ({
      name: feature.name,
      importance: Math.round(feature.importance * 100),
      value: feature.value,
    }))
    .sort((a, b) => b.importance - a.importance);

  const colors = ["#06b6d4", "#0891b2", "#0e7490", "#164e63", "#083344"];

  const [deepAnalysisLoading, setDeepAnalysisLoading] = useState(false);
  const [selectedVerbosity, setSelectedVerbosity] = useState<"brief" | "detailed" | "forensic">("detailed");

  if (isLoading) {
    return (
      <Card
        className="border-cyan-600 bg-cyan-950/10"
        style={{
          boxShadow:
            "0 0 15px rgba(34, 211, 238, 0.4), 0 0 30px rgba(34, 211, 238, 0.2)",
        }}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-cyan-400">
            <Brain className="w-5 h-5" />
            SHAP Explanation
          </CardTitle>
        </CardHeader>

        <CardContent>
          <div className="space-y-4 animate-pulse">
            <div className="h-4 bg-muted rounded w-1/2" />
            <div className="h-40 bg-muted rounded" />
            <div className="h-4 bg-muted rounded w-3/4" />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card
      className="border-cyan-600 bg-cyan-950/10"
      style={{
        boxShadow:
          "0 0 15px rgba(34, 211, 238, 0.4), 0 0 30px rgba(34, 211, 238, 0.2)",
      }}
    >
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-cyan-400">
          <Brain className="w-5 h-5" />
          SHAP Explanation
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">

        {/* Deep Analysis Section - Always Visible at Top */}
        {alertId && onDeepAnalysis && (
          <div className="space-y-2 p-3 bg-cyan-900/30 rounded border-2 border-cyan-500 sticky top-0 z-10">
            <div className="flex items-center gap-2">
              <FileText className="w-5 h-5 text-cyan-300" />
              <h3 className="text-sm font-bold text-cyan-300 uppercase tracking-wide">
                🚀 Get Deep LLM Analysis
              </h3>
            </div>

            {deepAnalysis ? (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-cyan-300 font-semibold">
                    Analysis Level: <span className="text-yellow-300">{deepAnalysisVerbosity}</span>
                  </span>
                </div>
                <p className="text-sm text-foreground/85 leading-relaxed bg-black/30 p-2 rounded">
                  {deepAnalysis}
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                <p className="text-xs text-cyan-200 font-medium">
                  📊 Generate AI-powered threat analysis with behavioral context and response recommendations
                </p>

                <div className="flex items-center gap-2">
                  <Select value={selectedVerbosity} onValueChange={(value: "brief" | "detailed" | "forensic") => setSelectedVerbosity(value)}>
                    <SelectTrigger className="w-full bg-cyan-950 border-cyan-600">
                      <SelectValue placeholder="Select depth..." />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="brief">📝 Brief - Quick summary</SelectItem>
                      <SelectItem value="detailed">📋 Detailed - Full analysis</SelectItem>
                      <SelectItem value="forensic">🔬 Forensic - Deep investigation</SelectItem>
                    </SelectContent>
                  </Select>

                  <Button
                    onClick={async () => {
                      if (!alertId) return;
                      setDeepAnalysisLoading(true);
                      try {
                        await onDeepAnalysis(alertId, selectedVerbosity);
                      } finally {
                        setDeepAnalysisLoading(false);
                      }
                    }}
                    disabled={deepAnalysisLoading}
                    size="sm"
                    className="bg-cyan-600 hover:bg-cyan-500 text-white font-bold whitespace-nowrap"
                  >
                    {deepAnalysisLoading ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      "▶ Generate"
                    )}
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Threat Type */}
        <div className="space-y-2">

          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-foreground/70">
              Threat Type
            </span>

            <Badge className="bg-red-600 text-white">
              {threatType}
            </Badge>
          </div>

          {shapValues && (
            <div className="flex items-center justify-between">

              <span className="text-sm font-medium text-foreground/70">
                Model Prediction
              </span>

              <div className="flex items-center gap-2">

                <div className="w-24 h-2 bg-background rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-red-500"
                    style={{
                      width: `${Math.min(shapValues.prediction * 100, 100)}%`,
                    }}
                  />
                </div>

                <span className="text-sm font-mono text-cyan-400">
                  {(shapValues.prediction * 100).toFixed(1)}%
                </span>

              </div>
            </div>
          )}
        </div>

        <div className="p-4 rounded border border-cyan-600/20 bg-slate-950/80 space-y-3">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-[0.16em] text-cyan-300/80">
                Attack Summary
              </p>
              <h3 className="text-lg font-semibold text-foreground">
                {threatType}
              </h3>
            </div>
            <Badge className="bg-red-600 text-white">
              {severity ?? "critical"}
            </Badge>
          </div>

          <p className="text-sm leading-6 text-foreground/75">
            {description ??
              `Packet from ${sourceIp ?? "unknown"} to ${destinationIp ?? "unknown"} was flagged as a potential ${threatType} attack.`}
          </p>

          <div className="grid grid-cols-2 gap-3 text-xs text-foreground/70">
            <div>
              <div className="font-medium text-foreground/80">Source</div>
              <div className="font-mono text-cyan-300">{sourceIp ?? "unknown"}</div>
            </div>
            <div>
              <div className="font-medium text-foreground/80">Destination</div>
              <div className="font-mono text-cyan-300">{destinationIp ?? "unknown"}</div>
            </div>
            <div>
              <div className="font-medium text-foreground/80">Protocol</div>
              <div className="font-mono text-cyan-300">{protocol ?? "unknown"}</div>
            </div>
            <div>
              <div className="font-medium text-foreground/80">Port</div>
              <div className="font-mono text-cyan-300">{port ?? "unknown"}</div>
            </div>
          </div>
        </div>


        {/* Feature Importance Chart */}

        {chartData.length > 0 ? (
          <div className="space-y-2">

            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-foreground">
                Feature Importance
              </h3>
            </div>

            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={chartData}>

                <CartesianGrid strokeDasharray="3 3" stroke="#1e3a4c" />

                <XAxis dataKey="name" stroke="#7dd3fc" fontSize={12} />

                <YAxis stroke="#7dd3fc" fontSize={12} />

                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "1px solid #06b6d4",
                    borderRadius: "4px",
                  }}
                  labelStyle={{ color: "#7dd3fc" }}
                />

                <Bar dataKey="importance" radius={[4, 4, 0, 0]}>

                  {(chartData ?? []).map((_, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={colors[index % colors.length]}
                    />
                  ))}

                </Bar>

              </BarChart>

            </ResponsiveContainer>

          </div>
        ) : (
          <div className="p-4 rounded border border-cyan-600/20 bg-background text-sm text-foreground/70">
            No SHAP feature importance is available for this alert yet.
          </div>
        )}


        {/* Feature List */}

        {chartData.length > 0 && (
          <div className="space-y-2">

            <h3 className="text-sm font-semibold text-foreground">
              Top Contributing Features
            </h3>

            <div className="space-y-1">

              {(chartData ?? []).slice(0, 3).map((feature, index) => (

                <div
                  key={index}
                  className="flex items-center justify-between text-xs p-2 bg-background rounded"
                >

                  <div className="flex items-center gap-2">

                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: colors[index % colors.length] }}
                    />

                    <span className="text-foreground/80">
                      {feature.name}
                    </span>

                  </div>

                  <div className="flex items-center gap-2">

                    <span className="font-mono text-cyan-400">
                      {feature.importance}%
                    </span>

                    <span className="text-foreground/50 max-w-xs truncate">
                      {feature.value}
                    </span>

                  </div>

                </div>

              ))}

            </div>

          </div>
        )}


        {/* LLM Explanation */}

        {llmExplanation && (
          <div className="space-y-2 p-3 bg-background rounded border border-cyan-600/30">

            <h3 className="text-sm font-semibold text-cyan-400">
              AI Analysis
            </h3>

            <p className="text-sm text-foreground/80 leading-relaxed">
              {llmExplanation}
            </p>

          </div>
        )}

      </CardContent>
    </Card>
  );
}