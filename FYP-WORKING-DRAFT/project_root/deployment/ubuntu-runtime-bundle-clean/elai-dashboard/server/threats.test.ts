import { describe, it, expect, vi, beforeEach } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

vi.mock("./db", () => ({
  getAlerts: vi.fn().mockResolvedValue([
    { id: 1, severity: "critical", threatType: "SQL Injection Attempt" },
  ]),
  getAlertById: vi.fn().mockResolvedValue({
    id: 1,
    threatType: "SQL Injection Attempt",
    sourceIp: "192.168.1.100",
  }),
  getAlertsBySeverity: vi.fn().mockResolvedValue([
    { id: 1, severity: "critical", threatType: "DDoS Attack" },
  ]),
  getBlockedIps: vi.fn().mockResolvedValue([
    { id: 1, ipAddress: "192.168.1.100" },
  ]),
  blockIp: vi.fn().mockResolvedValue({ insertId: 1 }),
  isIpBlocked: vi.fn().mockResolvedValue(null),
  unblockIp: vi.fn().mockResolvedValue({ changes: 1 }),
  getLatestSystemMetric: vi.fn().mockResolvedValue({
    cpuUsage: "45.2",
    memoryUsage: "62.1",
    networkLatency: "12.5",
  }),
  getSystemMetricsHistory: vi.fn().mockResolvedValue([{ cpuUsage: "45.2" }]),
  updateAlert: vi.fn().mockResolvedValue({ changes: 1 }),
}));

function createMockContext(): TrpcContext {
  return {
    user: {
      id: 1,
      openId: "test-user",
      email: "test@example.com",
      name: "Test User",
      role: "admin",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
      loginMethod: "test",
    },
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
}

describe("Threats Router", () => {
  let caller: ReturnType<typeof appRouter.createCaller>;

  beforeEach(() => {
    const ctx = createMockContext();
    caller = appRouter.createCaller(ctx);
  });

  it("should fetch alerts", async () => {
    const result = await caller.threats.getAlerts({ limit: 50, offset: 0 });
    expect(result).toBeDefined();
    expect(result?.[0]?.severity).toBe("critical");
  });

  it("should fetch alert by id", async () => {
    const result = await caller.threats.getAlertById({ id: 1 });
    expect(result).not.toBeNull();
    expect(result?.id).toBe(1);
  });

  it("should fetch alerts by severity", async () => {
    const result = await caller.threats.getAlertsBySeverity({
      severity: "critical",
      limit: 50,
    });

    expect(result).toBeDefined();
    expect(result?.[0]?.severity).toBe("critical");
  });

  it("should fetch explainable threats", async () => {
    const result = await caller.threats.listExplainable();
    expect(result).toBeDefined();
  });

  it("should block an IP", async () => {
    const result = await caller.threats.blockIp({
      ipAddress: "192.168.1.100",
    });

    expect(result.success).toBe(true);
  });

  it("should fetch blocked IPs", async () => {
    const result = await caller.threats.getBlockedIps();
    expect(result?.length).toBe(1);
  });

  it("should unblock an IP", async () => {
    const result = await caller.threats.unblockIp({
      ipAddress: "192.168.1.100",
    });

    expect(result.success).toBe(true);
  });

  it("should fetch latest metrics", async () => {
    const result = await caller.threats.getLatestMetrics();
    expect(result?.cpuUsage).toBe("45.2");
  });

  it("should fetch metrics history", async () => {
    const result = await caller.threats.getMetricsHistory({ limit: 100 });
    expect(result?.[0]?.cpuUsage).toBe("45.2");
  });

  it("should acknowledge alert", async () => {
    const result = await caller.threats.acknowledgeAlert({ id: 1 });
    expect(result.success).toBe(true);
  });

  it("should block alert source", async () => {
    const result = await caller.threats.blockAlertSource({ alertId: 1 });
    expect(result.success).toBe(true);
  });

  it("should export alerts", async () => {
    const result = await caller.threats.exportAlerts({ limit: 1000 });
    expect(result.alerts).toBeDefined();
  });
});