CREATE TABLE scan_dns_record (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    rtype VARCHAR(16) NOT NULL,
    value TEXT NOT NULL,
    CONSTRAINT fk_scan_dns_run FOREIGN KEY (run_id) REFERENCES scan_run (id) ON DELETE CASCADE,
    KEY idx_scan_dns_run (run_id),
    KEY idx_scan_dns_rtype (rtype)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
