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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

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
  onDeepAnalysis?: (
    alertId: number,
    verbosity: "brief" | "detailed" | "forensic"
  ) => Promise<void>;
  deepAnalysis?: string;
  deepAnalysisVerbosity?: "brief" | "detailed" | "forensic";
}

type ReportSection = {
  title: string;
  tone?: "neutral" | "warning";
  kind: "text" | "bullets" | "steps";
  content: string | string[];
};

const REPORT_MODE_LABELS: Record<
  NonNullable<ShapExplanationCardProps["deepAnalysisVerbosity"]>,
  string
> = {
  brief: "Executive",
  detailed: "SOC Analyst",
  forensic: "Forensic",
};

const SECTION_ORDER = [
  "Attack Vector",
  "Attacker Objective",
  "Immediate Actions Required",
  "Evidence Preservation",
  "Long-term Mitigation",
];

function normalizeAnalysisText(text: string) {
  return text.replace(/\r\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
}

function toSentenceList(text: string) {
  return text
    .split(/(?<=[.!?])\s+/)
    .map(sentence => sentence.trim())
    .filter(Boolean);
}

function toBulletItems(text: string) {
  return text
    .split("\n")
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => line.replace(/^[-*]\s*/, "").replace(/^\d+\.\s*/, "").trim())
    .filter(Boolean);
}

function extractSectionBlock(text: string, label: string) {
  const labelsPattern = SECTION_ORDER.map(entry =>
    entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  ).join("|");

  const sectionRegex = new RegExp(
    `${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:\\s*([\\s\\S]*?)(?=\\n(?:${labelsPattern}):|$)`,
    "i"
  );

  const match = text.match(sectionRegex);
  return match?.[1]?.trim() ?? "";
}

function getDefaultActions(threatType: string) {
  if (threatType.includes("SYN_Flood")) {
    return [
      "Rate limit inbound SYN traffic and review firewall or edge filtering rules.",
      "Verify whether the targeted service stayed available during the event window.",
      "Capture a short packet trace and preserve the firewall logs for the source IP.",
    ];
  }

  if (threatType.includes("Port_Scanning")) {
    return [
      "Block or rate limit the scanning source if the activity is unauthorized.",
      "Review the exposed services on the targeted ports for unnecessary exposure.",
      "Correlate the source IP with other reconnaissance or login events.",
    ];
  }

  return [
    "Review the source host and targeted service immediately.",
    "Collect the related logs and packet captures for the event window.",
    "Apply containment controls if the activity is confirmed malicious.",
  ];
}

function buildReportSections(
  analysis: string,
  verbosity: NonNullable<ShapExplanationCardProps["deepAnalysisVerbosity"]>,
  threatType: string
): { summary: string; sections: ReportSection[] } {
  const normalized = normalizeAnalysisText(analysis);

  if (!normalized) {
    return {
      summary: "No analysis text is available for this alert yet.",
      sections: [],
    };
  }

  const cleaned = normalized.replace(/^FORENSIC ANALYSIS - .*?\n*/i, "").trim();
  const sentences = toSentenceList(cleaned);
  const summary =
    verbosity === "brief"
      ? sentences.slice(0, 2).join(" ")
      : sentences.slice(0, 3).join(" ");

  const sections: ReportSection[] = [];

  const attackVector = extractSectionBlock(cleaned, "Attack Vector");
  sections.push({
    title: "Attack Summary",
    kind: "text",
    content: attackVector || summary || normalized,
  });

  const attackerObjective = extractSectionBlock(cleaned, "Attacker Objective");
  if (attackerObjective) {
    sections.push({
      title: "Attacker Objective",
      kind: "text",
      content: attackerObjective,
    });
  }

  const immediateActions = extractSectionBlock(
    cleaned,
    "Immediate Actions Required"
  );
  sections.push({
    title: "Immediate Actions",
    tone: "warning",
    kind: "steps",
    content: immediateActions
      ? toBulletItems(immediateActions)
      : getDefaultActions(threatType),
  });

  if (verbosity === "forensic") {
    const evidence = extractSectionBlock(cleaned, "Evidence Preservation");
    if (evidence) {
      sections.push({
        title: "Evidence Preservation",
        kind: "bullets",
        content: toBulletItems(evidence),
      });
    }

    const mitigation = extractSectionBlock(cleaned, "Long-term Mitigation");
    if (mitigation) {
      sections.push({
        title: "Long-term Mitigation",
        kind: "bullets",
        content: toBulletItems(mitigation),
      });
    }
  }

  if (verbosity === "detailed") {
    const extraNotes = sentences.slice(2);
    if (extraNotes.length > 0) {
      sections.push({
        title: "Analyst Notes",
        kind: "bullets",
        content: extraNotes,
      });
    }
  }

  return {
    summary: summary || normalized,
    sections,
  };
}

function renderSectionContent(section: ReportSection) {
  if (section.kind === "text") {
    return (
      <p className="text-sm leading-6 text-foreground/80">
        {section.content as string}
      </p>
    );
  }

  if (section.kind === "steps") {
    return (
      <ol className="space-y-2">
        {(section.content as string[]).map((item, index) => (
          <li
            key={`${section.title}-${index}`}
            className="flex items-start gap-3 text-sm text-foreground/80"
          >
            <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-cyan-950 text-xs font-semibold text-cyan-300">
              {index + 1}
            </span>
            <span className="leading-6">{item}</span>
          </li>
        ))}
      </ol>
    );
  }

  return (
    <ul className="space-y-2">
      {(section.content as string[]).map((item, index) => (
        <li
          key={`${section.title}-${index}`}
          className="flex items-start gap-3 text-sm text-foreground/80"
        >
          <span className="mt-2 h-2 w-2 shrink-0 rounded-full bg-cyan-400" />
          <span className="leading-6">{item}</span>
        </li>
      ))}
    </ul>
  );
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
    .map(feature => ({
      name: feature.name,
      importance: Math.round(feature.importance * 100),
      value: feature.value,
    }))
    .sort((a, b) => b.importance - a.importance);

  const colors = ["#06b6d4", "#0891b2", "#0e7490", "#164e63", "#083344"];
  const [deepAnalysisLoading, setDeepAnalysisLoading] = useState(false);
  const [selectedVerbosity, setSelectedVerbosity] = useState<
    "brief" | "detailed" | "forensic"
  >("detailed");

  const topIndicators = chartData.slice(0, 3);
  const reportVerbosity = deepAnalysisVerbosity ?? selectedVerbosity;
  const reportModeLabel = REPORT_MODE_LABELS[reportVerbosity];
  const report = deepAnalysis
    ? buildReportSections(deepAnalysis, reportVerbosity, threatType)
    : null;

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
        {alertId && onDeepAnalysis && (
          <div className="space-y-3 rounded border border-cyan-500/50 bg-cyan-950/20 p-4">
            <div className="flex items-center gap-2">
              <FileText className="w-5 h-5 text-cyan-300" />
              <h3 className="text-sm font-bold uppercase tracking-wide text-cyan-300">
                Deep Analysis Report
              </h3>
            </div>

            <div className="space-y-3 rounded border border-cyan-700/30 bg-slate-950/70 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs font-medium text-cyan-200">
                  {report
                    ? "Adjust the depth and regenerate this report whenever you need a different audience view."
                    : "Generate a cleaner report view for this alert, with depth matched to the audience you want."}
                </p>
                {report && (
                  <Badge className="bg-cyan-600 text-white">
                    Current report: {reportVerbosity}
                  </Badge>
                )}
              </div>

              <div className="flex items-center gap-2">
                <Select
                  value={selectedVerbosity}
                  onValueChange={(
                    value: "brief" | "detailed" | "forensic"
                  ) => setSelectedVerbosity(value)}
                >
                  <SelectTrigger className="w-full bg-cyan-950 border-cyan-600">
                    <SelectValue placeholder="Select depth..." />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="brief">
                      Executive - Quick summary
                    </SelectItem>
                    <SelectItem value="detailed">
                      SOC Analyst - Full analysis
                    </SelectItem>
                    <SelectItem value="forensic">
                      Forensic - Deep investigation
                    </SelectItem>
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
                  ) : report ? (
                    "Regenerate"
                  ) : (
                    "Generate"
                  )}
                </Button>
              </div>
            </div>

            {report ? (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <Badge className="bg-cyan-600 text-white">
                    {reportModeLabel}
                  </Badge>
                  <span className="font-semibold text-cyan-200">
                    Report depth:{" "}
                    <span className="text-yellow-300">{reportVerbosity}</span>
                  </span>
                </div>

                <div className="rounded border border-cyan-700/30 bg-slate-950/80 p-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-cyan-300/75">
                    Executive Summary
                  </p>
                  <p className="mt-2 text-sm leading-6 text-foreground/85">
                    {report.summary}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs text-foreground/70 md:grid-cols-5">
                  <div className="rounded border border-cyan-700/20 bg-background p-3">
                    <div className="font-medium text-foreground/80">Source</div>
                    <div className="mt-1 font-mono text-cyan-300">
                      {sourceIp ?? "unknown"}
                    </div>
                  </div>
                  <div className="rounded border border-cyan-700/20 bg-background p-3">
                    <div className="font-medium text-foreground/80">
                      Destination
                    </div>
                    <div className="mt-1 font-mono text-cyan-300">
                      {destinationIp ?? "unknown"}
                    </div>
                  </div>
                  <div className="rounded border border-cyan-700/20 bg-background p-3">
                    <div className="font-medium text-foreground/80">Protocol</div>
                    <div className="mt-1 font-mono text-cyan-300">
                      {protocol ?? "unknown"}
                    </div>
                  </div>
                  <div className="rounded border border-cyan-700/20 bg-background p-3">
                    <div className="font-medium text-foreground/80">Port</div>
                    <div className="mt-1 font-mono text-cyan-300">
                      {port ?? "unknown"}
                    </div>
                  </div>
                  <div className="rounded border border-cyan-700/20 bg-background p-3">
                    <div className="font-medium text-foreground/80">Severity</div>
                    <div className="mt-1 font-semibold text-cyan-300">
                      {severity ?? "unknown"}
                    </div>
                  </div>
                </div>

                {topIndicators.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300/75">
                      Key Indicators
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {topIndicators.map((feature, index) => (
                        <div
                          key={feature.name}
                          className="min-w-[170px] rounded border border-cyan-700/20 bg-background px-3 py-2"
                        >
                          <div className="flex items-center gap-2">
                            <span
                              className="h-2 w-2 rounded-full"
                              style={{
                                backgroundColor: colors[index % colors.length],
                              }}
                            />
                            <span className="text-sm font-medium text-foreground">
                              {feature.name}
                            </span>
                          </div>
                          <div className="mt-1 text-xs text-cyan-300">
                            Impact {feature.importance}%
                            {feature.value ? ` | Value ${feature.value}` : ""}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="max-h-[420px] space-y-3 overflow-y-auto pr-1">
                  {report.sections.map(section => (
                    <div
                      key={section.title}
                      className={`rounded border p-4 ${
                        section.tone === "warning"
                          ? "border-amber-500/30 bg-amber-950/20"
                          : "border-cyan-700/20 bg-background"
                      }`}
                    >
                      <h4 className="mb-3 text-sm font-semibold text-cyan-300">
                        {section.title}
                      </h4>
                      {renderSectionContent(section)}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        )}

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-foreground/70">
              Threat Type
            </span>

            <Badge className="bg-red-600 text-white">{threatType}</Badge>
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
              `Packet from ${sourceIp ?? "unknown"} to ${
                destinationIp ?? "unknown"
              } was flagged as a potential ${threatType} attack.`}
          </p>

          <div className="grid grid-cols-2 gap-3 text-xs text-foreground/70">
            <div>
              <div className="font-medium text-foreground/80">Source</div>
              <div className="font-mono text-cyan-300">
                {sourceIp ?? "unknown"}
              </div>
            </div>
            <div>
              <div className="font-medium text-foreground/80">Destination</div>
              <div className="font-mono text-cyan-300">
                {destinationIp ?? "unknown"}
              </div>
            </div>
            <div>
              <div className="font-medium text-foreground/80">Protocol</div>
              <div className="font-mono text-cyan-300">
                {protocol ?? "unknown"}
              </div>
            </div>
            <div>
              <div className="font-medium text-foreground/80">Port</div>
              <div className="font-mono text-cyan-300">
                {port ?? "unknown"}
              </div>
            </div>
          </div>
        </div>

        {llmExplanation && (
          <div className="p-4 rounded border border-cyan-600/20 bg-background space-y-2">
            <p className="text-xs uppercase tracking-[0.16em] text-cyan-300/80">
              Analyst Narrative
            </p>
            <p className="text-sm leading-6 text-foreground/75">
              {llmExplanation}
            </p>
          </div>
        )}

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

        {chartData.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-foreground">
              Top Contributing Features
            </h3>

            <div className="space-y-1">
              {(chartData ?? []).slice(0, 3).map((feature, index) => (
                <div
                  key={feature.name}
                  className="flex items-center justify-between text-xs p-2 bg-background rounded"
                >
                  <div className="flex items-center gap-2">
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: colors[index % colors.length] }}
                    />

                    <span className="text-foreground/80">{feature.name}</span>
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
      </CardContent>
    </Card>
  );
}
