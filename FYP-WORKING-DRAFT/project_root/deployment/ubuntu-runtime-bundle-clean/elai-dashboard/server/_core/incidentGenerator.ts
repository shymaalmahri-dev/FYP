import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import { fileURLToPath } from "url";

const execFileAsync = promisify(execFile);
const pythonExecutable = process.env.PYTHON_PATH || "python";

const INCIDENT_GENERATOR_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "explainable_ai",
  "incident_generator.py"
);

export async function generateDeepAnalysisWithPython(
  attackType: string,
  attackerIp: string,
  features: Array<Record<string, unknown>>,
  verbosity: "brief" | "detailed" | "forensic"
): Promise<string> {
  const args = [
    INCIDENT_GENERATOR_PATH,
    "--attack-type",
    attackType,
    "--attacker-ip",
    attackerIp,
    "--verbosity",
    verbosity,
    "--features",
    JSON.stringify(features ?? []),
  ];

  const { stdout, stderr } = await execFileAsync(pythonExecutable, args, {
    timeout: 45000,
    maxBuffer: 20 * 1024 * 1024,
  });

  if (stderr && stderr.toString().trim().length > 0) {
    console.warn("[Python LLM] stderr:", stderr.toString().trim());
  }

  // If output is JSON, parse and return the analysis field
  try {
    const parsed = JSON.parse(stdout.toString().trim());
    if (parsed.analysis) return parsed.analysis;
    return stdout.toString().trim();
  } catch {
    return stdout.toString().trim();
  }
}
