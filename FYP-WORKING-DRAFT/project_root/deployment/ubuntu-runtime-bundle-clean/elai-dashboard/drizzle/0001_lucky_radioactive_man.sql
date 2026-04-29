CREATE TABLE `alerts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`timestamp` timestamp NOT NULL DEFAULT (now()),
	`severity` enum('critical','high','medium','low') NOT NULL,
	`threatType` varchar(128) NOT NULL,
	`sourceIp` varchar(45) NOT NULL,
	`destinationIp` varchar(45) NOT NULL,
	`protocol` varchar(32),
	`port` int,
	`description` text,
	`modelConfidence` varchar(10),
	`isBlocked` int NOT NULL DEFAULT 0,
	`shapeExplanation` text,
	`llmExplanation` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `alerts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `blockedIps` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ipAddress` varchar(45) NOT NULL,
	`reason` text,
	`blockedBy` varchar(64),
	`blockedAt` timestamp NOT NULL DEFAULT (now()),
	`unblockAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `blockedIps_id` PRIMARY KEY(`id`),
	CONSTRAINT `blockedIps_ipAddress_unique` UNIQUE(`ipAddress`)
);
--> statement-breakpoint
CREATE TABLE `systemMetrics` (
	`id` int AUTO_INCREMENT NOT NULL,
	`timestamp` timestamp NOT NULL DEFAULT (now()),
	`cpuUsage` varchar(10) NOT NULL,
	`memoryUsage` varchar(10) NOT NULL,
	`memoryTotal` varchar(20) NOT NULL,
	`networkLatency` varchar(10) NOT NULL,
	`diskUsage` varchar(10),
	`activeConnections` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `systemMetrics_id` PRIMARY KEY(`id`)
);
