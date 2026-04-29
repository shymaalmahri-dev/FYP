type ExportAlert = {
  id?: number | null;
  timestamp?: Date | string | null;
  severity?: string | null;
  threatType?: string | null;
  sourceIp?: string | null;
  destinationIp?: string | null;
  protocol?: string | null;
  port?: number | null;
  modelConfidence?: string | null;
  isBlocked?: number | null;
  description?: string | null;
  llmExplanation?: string | null;
  deepAnalysis?: string | null;
};

const escapeCsv = (value: unknown) => {
  const text = String(value ?? "");
  if (/[,"\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
};

const sanitizePdfText = (value: string) =>
  value
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)")
    .replace(/[^\x20-\x7E]/g, " ");

export function buildAlertsCsv(alerts: ExportAlert[]) {
  const header = [
    "id",
    "timestamp",
    "severity",
    "threatType",
    "sourceIp",
    "destinationIp",
    "protocol",
    "port",
    "modelConfidence",
    "isBlocked",
    "description",
    "llmExplanation",
    "deepAnalysis",
  ];

  const rows = alerts.map(alert => [
    alert.id ?? "",
    alert.timestamp instanceof Date ? alert.timestamp.toISOString() : alert.timestamp ?? "",
    alert.severity ?? "",
    alert.threatType ?? "",
    alert.sourceIp ?? "",
    alert.destinationIp ?? "",
    alert.protocol ?? "",
    alert.port ?? "",
    alert.modelConfidence ?? "",
    alert.isBlocked ?? 0,
    alert.description ?? "",
    alert.llmExplanation ?? "",
    alert.deepAnalysis ?? "",
  ]);

  return [header, ...rows].map(row => row.map(escapeCsv).join(",")).join("\n");
}

function buildPdfObjects(lines: string[]) {
  const contentLines: string[] = ["BT", "/F1 10 Tf", "40 780 Td", "14 TL"];

  lines.forEach((line, index) => {
    const safeLine = sanitizePdfText(line);
    if (index === 0) {
      contentLines.push(`(${safeLine}) Tj`);
    } else {
      contentLines.push("T*");
      contentLines.push(`(${safeLine}) Tj`);
    }
  });

  contentLines.push("ET");
  const contentStream = contentLines.join("\n");

  return [
    "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
    "2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj",
    "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
    "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    `5 0 obj << /Length ${contentStream.length} >> stream\n${contentStream}\nendstream endobj`,
  ];
}

export function buildAlertsPdf(alerts: ExportAlert[]) {
  const lines = [
    "ELAI Alert Report",
    `Generated: ${new Date().toISOString()}`,
    `Total alerts: ${alerts.length}`,
    "",
  ];

  alerts.slice(0, 40).forEach((alert, index) => {
    const timestamp = alert.timestamp instanceof Date ? alert.timestamp.toISOString() : String(alert.timestamp ?? "");
    lines.push(
      `${index + 1}. [${alert.severity ?? "unknown"}] ${alert.threatType ?? "Unknown threat"} | ${timestamp}`
    );
    lines.push(`   Source: ${alert.sourceIp ?? "unknown"} -> ${alert.destinationIp ?? "unknown"}  Port: ${alert.port ?? "-"}`);
    if (alert.description) {
      lines.push(`   Summary: ${String(alert.description).slice(0, 110)}`);
    }
    lines.push("");
  });

  const objects = buildPdfObjects(lines);
  const header = "%PDF-1.4\n";
  let body = "";
  const offsets = [0];

  for (const object of objects) {
    offsets.push(header.length + body.length);
    body += `${object}\n`;
  }

  const xrefOffset = header.length + body.length;
  let xref = `xref\n0 ${objects.length + 1}\n`;
  xref += "0000000000 65535 f \n";
  offsets.slice(1).forEach(offset => {
    xref += `${String(offset).padStart(10, "0")} 00000 n \n`;
  });

  const trailer = `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return `${header}${body}${xref}${trailer}`;
}
