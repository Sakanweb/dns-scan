CREATE TABLE scan_target (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    input VARCHAR(255) NOT NULL,
    kind ENUM('ip', 'domain') NOT NULL,
    value VARCHAR(255) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uq_scan_target_kind_value (kind, value),
    KEY idx_scan_target_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
