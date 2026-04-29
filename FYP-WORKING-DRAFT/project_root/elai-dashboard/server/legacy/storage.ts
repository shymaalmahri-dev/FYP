import {
  InsertAlert,
  InsertSystemMetric,
  InsertBlockedIp,
} from "../drizzle/schema";

type Alert = InsertAlert & { id: number };
type Metric = InsertSystemMetric & { id: number };
type BlockedIp = InsertBlockedIp;

class Storage {
  private alerts: Alert[] = [];
  private metrics: Metric[] = [];
  private blockedIps: BlockedIp[] = [];

  private alertId = 1;
  private metricId = 1;

  /* ---------------- Alerts ---------------- */

  createAlert(alert: InsertAlert): Alert {
    const newAlert: Alert = {
      ...alert,
      id: this.alertId++,
    };

    this.alerts.push(newAlert);
    return newAlert;
  }

  getAlerts(limit = 50, offset = 0): Alert[] {
    return this.alerts
      .slice()
      .sort((a, b) => {
        const t1 = new Date(a.timestamp ?? 0).getTime();
        const t2 = new Date(b.timestamp ?? 0).getTime();
        return t2 - t1;
      })
      .slice(offset, offset + limit);
  }

  getAlertById(id: number): Alert | undefined {
    return this.alerts.find((a) => a.id === id);
  }

  updateAlert(id: number, updates: Partial<InsertAlert>) {
    const alert = this.getAlertById(id);
    if (!alert) return;

    Object.assign(alert, updates);
  }

  /* ---------------- Metrics ---------------- */

  createMetric(metric: InsertSystemMetric): Metric {
    const newMetric: Metric = {
      ...metric,
      id: this.metricId++,
    };

    this.metrics.push(newMetric);
    return newMetric;
  }

  getLatestMetric(): Metric | undefined {
    return this.metrics[this.metrics.length - 1];
  }

  getMetricsHistory(limit = 100): Metric[] {
    return this.metrics.slice(-limit).reverse();
  }

  /* ---------------- Blocked IPs ---------------- */

  blockIp(ip: InsertBlockedIp) {
    const exists = this.blockedIps.find(
      (b) => b.ipAddress === ip.ipAddress
    );

    if (!exists) {
      this.blockedIps.push(ip);
    }
  }

  getBlockedIps(): BlockedIp[] {
    return this.blockedIps;
  }

  unblockIp(ipAddress: string) {
    this.blockedIps = this.blockedIps.filter(
      (b) => b.ipAddress !== ipAddress
    );
  }

  isBlocked(ipAddress: string): BlockedIp | undefined {
    return this.blockedIps.find(
      (b) => b.ipAddress === ipAddress
    );
  }
}

export const storage = new Storage();