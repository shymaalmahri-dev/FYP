import { Server as SocketIOServer } from "socket.io";
import { Server as HTTPServer } from "http";
import { ingestNewExplainableThreats } from "./threatDetection";
import { createSystemMetric, getAlerts } from "./db";

export interface SystemMetrics {
  cpuUsage: number;
  memoryUsage: number;
  memoryTotal: number;
  networkLatency: number;
  diskUsage: number;
  activeConnections: number;
  timestamp: Date;
}

let io: SocketIOServer | null = null;
let threatInterval: NodeJS.Timeout | null = null;
let metricsInterval: NodeJS.Timeout | null = null;
const enableFileAlertIngestion = process.env.ENABLE_FILE_ALERT_INGESTION === "true";

export function initializeWebSocket(httpServer: HTTPServer) {

  io = new SocketIOServer(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"],
    },
  });

  io.on("connection", (socket) => {

    console.log(`[WebSocket] Client connected: ${socket.id}`);

    socket.on("request-initial-data", async () => {
      const alerts = await getAlerts(50, 0);

      socket.emit("initial-data", {
        alerts,
        metrics: generateSystemMetrics(),
      });
    });

    socket.on("disconnect", () => {
      console.log(`[WebSocket] Client disconnected: ${socket.id}`);
    });

  });

  if (enableFileAlertIngestion) {
    startThreatSimulation();
  } else {
    console.log("[WebSocket] File-based alert ingestion disabled; dashboard expects direct alert posts.");
  }
  startMetricsSimulation();

  return io;
}

function generateSystemMetrics(): SystemMetrics {

  return {
    cpuUsage: Math.random() * 100,
    memoryUsage: Math.random() * 100,
    memoryTotal: 16384,
    networkLatency: Math.random() * 50,
    diskUsage: Math.random() * 100,
    activeConnections: Math.floor(Math.random() * 100),
    timestamp: new Date(),
  };

}

function startThreatSimulation() {

  threatInterval = setInterval(() => {

    ingestNewExplainableThreats().catch((error) => {
      console.warn("[WebSocket] Failed ingesting file-based alerts:", error);
    });

  }, 5000);

}

function startMetricsSimulation() {

  metricsInterval = setInterval(async () => {

    const metrics = generateSystemMetrics();

    try {
      await createSystemMetric(metrics as any);
    } catch (err) {
      console.warn("[Metrics] DB write failed");
    }

    io?.emit("system-metrics", metrics);

  }, 2000);

}

export function stopWebSocketSimulations() {

  if (threatInterval) clearInterval(threatInterval);
  if (metricsInterval) clearInterval(metricsInterval);

}

export function getWebSocketServer() {
  return io;
}

export function broadcastAlert(alert: any) {
  io?.emit("new-alert", alert);
}
