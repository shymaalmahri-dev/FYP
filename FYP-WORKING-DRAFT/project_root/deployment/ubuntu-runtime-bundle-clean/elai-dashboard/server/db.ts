import { eq, desc } from "drizzle-orm";
import { drizzle, MySql2Database } from "drizzle-orm/mysql2";
import mysql from "mysql2/promise";

import {
  InsertUser,
  users,
  InsertAlert,
  alerts,
  InsertSystemMetric,
  systemMetrics,
  InsertBlockedIp,
  blockedIps,
} from "../drizzle/schema";

import { ENV } from "./_core/env";

/* -------------------- DB Instance -------------------- */

let _db: MySql2Database | null = null;

async function initDb(): Promise<MySql2Database | null> {
  if (_db) return _db;

  if (!process.env.DATABASE_URL) {
    console.warn("[DB] DATABASE_URL missing");
    return null;
  }

  try {
    const pool = mysql.createPool({
      uri: process.env.DATABASE_URL,
      connectionLimit: 10,
    });

    _db = drizzle(pool);

    console.log("[DB] Connected");

    return _db;
  } catch (err) {
    console.error("[DB] Connection failed", err);
    return null;
  }
}

export async function getDb(): Promise<MySql2Database | null> {
  return initDb();
}

export async function checkDatabaseHealth() {
  const db = await getDb();
  if (!db) {
    return {
      ok: false,
      message: "DATABASE_URL missing or database unavailable",
    };
  }

  try {
    await (db as any).execute("SELECT 1 AS ok");
    return {
      ok: true,
      message: "Database reachable",
    };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Database ping failed",
    };
  }
}

/* -------------------- Users -------------------- */

export async function upsertUser(user: InsertUser) {
  const db = await getDb();
  if (!db) return;

  if (!user.openId) throw new Error("User openId required");

  const values: any = {
    openId: user.openId,
    name: user.name ?? null,
    email: user.email ?? null,
    loginMethod: user.loginMethod ?? null,
    lastSignedIn: user.lastSignedIn ?? new Date(),
  };

  if (user.role) {
    values.role = user.role;
  } else if (user.openId === ENV.ownerOpenId) {
    values.role = "admin";
  }

  await db
    .insert(users)
    .values(values)
    .onDuplicateKeyUpdate({
      set: values,
    });
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;

  const result = await db
    .select()
    .from(users)
    .where(eq(users.openId, openId))
    .limit(1);

  return result[0];
}

/* -------------------- Alerts -------------------- */

export async function createAlert(alert: InsertAlert) {
  const db = await getDb();
  if (!db) return null;

  // ✅ Remove `id` so MySQL auto-generates it
  const { id, ...alertData } = alert;

  const result = await db.insert(alerts).values(alertData);
  const insertId = Number((result as any)?.[0]?.insertId ?? (result as any)?.insertId ?? 0);

  return {
    ...alertData,
    id: insertId || undefined,
  };
}

export async function getAlerts(limit = 50, offset = 0) {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(alerts)
    .orderBy(desc(alerts.timestamp))
    .limit(limit)
    .offset(offset);
}

export async function getAlertCount() {
  const db = await getDb();
  if (!db) return 0;

  try {
    const result = await (db as any).execute("SELECT COUNT(*) AS count FROM alerts");
    const rows = Array.isArray(result) ? result[0] : result;
    if (Array.isArray(rows) && rows.length > 0) {
      return Number((rows[0] as any).count ?? 0);
    }

    if (rows && typeof rows === "object") {
      return Number((rows as any).count ?? 0);
    }
  } catch (error) {
    console.error("[DB] Failed to count alerts:", error);
  }

  return 0;
}

export async function getAlertById(id: number) {
  const db = await getDb();
  if (!db) return null;

  const result = await db
    .select()
    .from(alerts)
    .where(eq(alerts.id, id))
    .limit(1);

  return result[0] ?? null;
}

export async function getAlertsBySeverity(
  severity: "critical" | "high" | "medium" | "low",
  limit = 50
) {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(alerts)
    .where(eq(alerts.severity, severity))
    .orderBy(desc(alerts.timestamp))
    .limit(limit);
}

export async function updateAlert(
  id: number,
  updates: Partial<InsertAlert>
) {
  const db = await getDb();
  if (!db) return;

  await db.update(alerts).set(updates).where(eq(alerts.id, id));
}

/* -------------------- System Metrics -------------------- */

export async function createSystemMetric(metric: InsertSystemMetric) {
  const db = await getDb();
  if (!db) return;

  try {
    await db.insert(systemMetrics).values({
      cpuUsage: String(metric.cpuUsage),
      memoryUsage: String(metric.memoryUsage),
      memoryTotal: String(metric.memoryTotal),
      networkLatency: String(metric.networkLatency),
      diskUsage: String(metric.diskUsage ?? 0),
      activeConnections: Number(metric.activeConnections ?? 0),
      timestamp:
        metric.timestamp instanceof Date
          ? metric.timestamp
          : new Date(metric.timestamp ?? Date.now()),
    });
  } catch (e) {
    console.error("[Metrics] Failed writing metric:", e);
  }
}

export async function getLatestSystemMetric() {
  const db = await getDb();
  if (!db) return null;

  const result = await db
    .select()
    .from(systemMetrics)
    .orderBy(desc(systemMetrics.timestamp))
    .limit(1);

  return result[0] ?? null;
}

export async function getSystemMetricsHistory(limit = 100) {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(systemMetrics)
    .orderBy(desc(systemMetrics.timestamp))
    .limit(limit);
}

/* -------------------- Blocked IPs -------------------- */

export async function blockIp(ip: InsertBlockedIp) {
  const db = await getDb();
  if (!db) return;

  await db.insert(blockedIps).values(ip);
}

export async function getBlockedIps() {
  const db = await getDb();
  if (!db) return [];

  return db
    .select()
    .from(blockedIps)
    .orderBy(desc(blockedIps.blockedAt));
}

export async function isIpBlocked(ipAddress: string) {
  const db = await getDb();
  if (!db) return null;

  const result = await db
    .select()
    .from(blockedIps)
    .where(eq(blockedIps.ipAddress, ipAddress))
    .limit(1);

  return result[0] ?? null;
}

export async function unblockIp(ipAddress: string) {
  const db = await getDb();
  if (!db) return;

  await db.delete(blockedIps).where(eq(blockedIps.ipAddress, ipAddress));
}
