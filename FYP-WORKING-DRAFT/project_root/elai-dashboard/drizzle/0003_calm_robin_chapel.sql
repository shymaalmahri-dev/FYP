ALTER TABLE `alerts` ADD `deepAnalysis` text;--> statement-breakpoint
ALTER TABLE `alerts` ADD `deepAnalysisVerbosity` enum('brief','detailed','forensic');--> statement-breakpoint
ALTER TABLE `alerts` ADD `acknowledged` int DEFAULT 0 NOT NULL;