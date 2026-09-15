CREATE TABLE scan_host (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    kind ENUM('confirmed', 'wildcard', 'unresolved') NOT NULL,
    ips_json JSON NULL,
    cname_json JSON NULL,
    sources_json JSON NOT NULL,
    CONSTRAINT fk_scan_host_run FOREIGN KEY (run_id) REFERENCES scan_run (id) ON DELETE CASCADE,
    UNIQUE KEY uq_scan_host_run_name (run_id, name),
    KEY idx_scan_host_kind (kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
