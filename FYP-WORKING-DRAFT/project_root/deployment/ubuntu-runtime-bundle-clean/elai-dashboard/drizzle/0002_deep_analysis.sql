-- Add deep analysis fields to alerts table
ALTER TABLE alerts ADD COLUMN deepAnalysis TEXT;
ALTER TABLE alerts ADD COLUMN deepAnalysisVerbosity ENUM('brief', 'detailed', 'forensic');
ALTER TABLE alerts ADD COLUMN acknowledged INT DEFAULT 0 NOT NULL;