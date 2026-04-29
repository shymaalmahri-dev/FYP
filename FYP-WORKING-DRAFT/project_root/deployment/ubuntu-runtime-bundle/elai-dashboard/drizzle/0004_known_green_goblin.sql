ALTER TABLE `systemMetrics` MODIFY COLUMN `cpuUsage` varchar(20) NOT NULL;--> statement-breakpoint
ALTER TABLE `systemMetrics` MODIFY COLUMN `memoryUsage` varchar(20) NOT NULL;--> statement-breakpoint
ALTER TABLE `systemMetrics` MODIFY COLUMN `networkLatency` varchar(20) NOT NULL;--> statement-breakpoint
ALTER TABLE `systemMetrics` MODIFY COLUMN `diskUsage` varchar(20);