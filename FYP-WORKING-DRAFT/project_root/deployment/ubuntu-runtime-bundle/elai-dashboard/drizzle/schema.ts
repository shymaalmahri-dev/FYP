import { int, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Security alerts table for storing threat detection results
 */
export const alerts = mysqlTable("alerts", {
  id: int("id").autoincrement().primaryKey(),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).notNull(),
  threatType: varchar("threatType", { length: 128 }).notNull(),
  sourceIp: varchar("sourceIp", { length: 45 }).notNull(),
  destinationIp: varchar("destinationIp", { length: 45 }).notNull(),
  protocol: varchar("protocol", { length: 32 }),
  port: int("port"),
  description: text("description"),
  modelConfidence: varchar("modelConfidence", { length: 10 }),
  isBlocked: int("isBlocked").default(0).notNull(),
  shapeExplanation: text("shapeExplanation"),
  llmExplanation: text("llmExplanation"),
  deepAnalysis: text("deepAnalysis"),
  deepAnalysisVerbosity: mysqlEnum("deepAnalysisVerbosity", ["brief", "detailed", "forensic"]),
  acknowledged: int("acknowledged").default(0).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = typeof alerts.$inferInsert;

/**
 * System metrics table for storing CPU, memory, and network latency data
 */
export const systemMetrics = mysqlTable("systemMetrics", {
  id: int("id").autoincrement().primaryKey(),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  cpuUsage: varchar("cpuUsage", { length: 20 }).notNull(),
  memoryUsage: varchar("memoryUsage", { length: 20 }).notNull(),
  memoryTotal: varchar("memoryTotal", { length: 20 }).notNull(),
  networkLatency: varchar("networkLatency", { length: 20 }).notNull(),
  diskUsage: varchar("diskUsage", { length: 20 }),
  activeConnections: int("activeConnections"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type SystemMetric = typeof systemMetrics.$inferSelect;
export type InsertSystemMetric = typeof systemMetrics.$inferInsert;

/**
 * Blocked IPs table for tracking security actions
 */
export const blockedIps = mysqlTable("blockedIps", {
  id: int("id").autoincrement().primaryKey(),
  ipAddress: varchar("ipAddress", { length: 45 }).notNull().unique(),
  reason: text("reason"),
  blockedBy: varchar("blockedBy", { length: 64 }),
  blockedAt: timestamp("blockedAt").defaultNow().notNull(),
  unblockAt: timestamp("unblockAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type BlockedIp = typeof blockedIps.$inferSelect;
export type InsertBlockedIp = typeof blockedIps.$inferInsert;