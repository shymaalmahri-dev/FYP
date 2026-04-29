import mysql from 'mysql2/promise';
import { config } from 'dotenv';

config();

async function checkAlerts() {
  const connection = await mysql.createConnection(process.env.DATABASE_URL);
  try {
    const [rows] = await connection.execute(
      'SELECT id, threatType, sourceIp, deepAnalysis, deepAnalysisVerbosity FROM alerts ORDER BY id DESC LIMIT 5'
    );
    console.log('Recent alerts:');
    rows.forEach(row => {
      console.log(`ID: ${row.id}, Type: ${row.threatType}, IP: ${row.sourceIp}, Deep Analysis: ${row.deepAnalysis ? 'YES' : 'NO'}, Verbosity: ${row.deepAnalysisVerbosity || 'NONE'}`);
    });
  } catch (error) {
    console.error('Error:', error);
  } finally {
    connection.end();
  }
}

checkAlerts();