ALTER TABLE `alerts`
  ADD COLUMN `eventCategory` varchar(32) NOT NULL DEFAULT 'malicious',
  ADD COLUMN `primaryPrediction` varchar(128),
  ADD COLUMN `secondaryPrediction` varchar(128),
  ADD COLUMN `primaryConfidence` varchar(10),
  ADD COLUMN `secondaryConfidence` varchar(10),
  ADD COLUMN `confidenceGap` varchar(10),
  ADD COLUMN `recommendedAction` varchar(64),
  ADD COLUMN `blockStatus` varchar(32) NOT NULL DEFAULT 'not_requested',
  ADD COLUMN `blockMessage` text,
  ADD COLUMN `blockUpdatedAt` timestamp NULL,
  ADD COLUMN `edgeDevice` varchar(128);
