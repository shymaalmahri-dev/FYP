import mysql from 'mysql2/promise';
import { config } from 'dotenv';

config();

async function updateSchema() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.error('DATABASE_URL not found');
    return;
  }

  const connection = await mysql.createConnection(dbUrl);
  try {
    await connection.execute(`
      ALTER TABLE systemMetrics
      MODIFY COLUMN cpuUsage VARCHAR(20),
      MODIFY COLUMN memoryUsage VARCHAR(20),
      MODIFY COLUMN networkLatency VARCHAR(20),
      MODIFY COLUMN diskUsage VARCHAR(20)
    `);
    console.log('Schema updated successfully');
  } catch (error) {
    console.error('Error updating schema:', error);
  } finally {
    connection.end();
  }
}

updateSchema();