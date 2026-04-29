import "dotenv/config";
import http from "http";
import express from "express";
import cors from "cors";
import * as trpcExpress from "@trpc/server/adapters/express";

import { appRouter } from "./routers";
import { createContext } from "./_core/context";
import { setupVite, serveStatic } from "./_core/vite";
import { createAlert, blockIp, isIpBlocked } from "./db";
import { initializeWebSocket, broadcastAlert } from "./websocket";

const app = express();

app.use(cors());
app.use(express.json());

app.post("/api/alerts", async (req, res) => {
  const payload = req.body;

  if (!payload || !payload.sourceIp || !payload.threatType) {
    return res.status(400).json({
      success: false,
      error: "Invalid alert payload: sourceIp and threatType are required",
    });
  }

  const alert = {
    timestamp: payload.timestamp ? new Date(payload.timestamp) : new Date(),
    severity: payload.severity || "high",
    eventCategory: payload.eventCategory || "malicious",
    threatType: payload.threatType,
    sourceIp: payload.sourceIp,
    destinationIp: payload.destinationIp || "unknown",
    protocol: payload.protocol || null,
    port:
      typeof payload.port === "number"
        ? payload.port
        : payload.port
          ? Number(payload.port)
          : null,
    description: payload.description ?? null,
    modelConfidence: payload.modelConfidence ?? null,
    primaryPrediction: payload.primaryPrediction ?? null,
    secondaryPrediction: payload.secondaryPrediction ?? null,
    primaryConfidence: payload.primaryConfidence ?? null,
    secondaryConfidence: payload.secondaryConfidence ?? null,
    confidenceGap: payload.confidenceGap ?? null,
    recommendedAction: payload.recommendedAction ?? null,
    isBlocked: typeof payload.isBlocked === "number" ? payload.isBlocked : 0,
    blockStatus: payload.blockStatus ?? "not_requested",
    blockMessage: payload.blockMessage ?? null,
    blockUpdatedAt: payload.blockUpdatedAt ? new Date(payload.blockUpdatedAt) : null,
    edgeDevice: payload.edgeDevice ?? null,
    shapeExplanation: payload.shapeExplanation ?? null,
    llmExplanation: payload.llmExplanation ?? null,
  };

  try {
    const storedAlert = await createAlert(alert as any);
    if (alert.blockStatus === "blocked" && alert.sourceIp) {
      const existing = await isIpBlocked(alert.sourceIp);
      if (!existing) {
        await blockIp({
          ipAddress: alert.sourceIp,
          reason: alert.blockMessage || "Auto-blocked by edge device",
          blockedBy: alert.edgeDevice || "EDGE",
        } as any);
      }
    }
    broadcastAlert(storedAlert ?? alert);
    return res.status(201).json({ success: true, alert: storedAlert ?? alert });
  } catch (error) {
    console.error("[Alerts API] Failed to store alert:", error);
    return res.status(500).json({
      success: false,
      error: "Unable to save alert to database",
    });
  }
});

app.use(
  "/api/trpc",
  trpcExpress.createExpressMiddleware({
    router: appRouter,
    createContext,
  })
);

const server = http.createServer(app);
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;

async function bootstrap() {
  initializeWebSocket(server);

  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  console.log(`[ENV] DATABASE_URL is ${process.env.DATABASE_URL ? "set" : "missing"}`);
  console.log(`[ENV] OAUTH_SERVER_URL is ${process.env.OAUTH_SERVER_URL ? "set" : "missing"}`);

  server.on("error", (error) => {
    if ((error as any).code === "EADDRINUSE") {
      console.error(`[ERROR] Port ${PORT} is already in use. Stop the existing dashboard process or set PORT to another available port.`);
    } else {
      console.error("[ERROR] Server error:", error);
    }
    process.exit(1);
  });

  server.listen(PORT, () => {
    console.log(`ELAI server running at http://localhost:${PORT}`);
    console.log(`tRPC endpoint: http://localhost:${PORT}/api/trpc`);
    console.log("WebSocket ready");
  });
}

bootstrap().catch((error) => {
  console.error("[Bootstrap] Failed to start server:", error);
  process.exit(1);
});
