CREATE TABLE scan_http_check (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    host_id BIGINT UNSIGNED NOT NULL,
    works TINYINT(1) NOT NULL DEFAULT 0,
    status_code INT NULL,
    title VARCHAR(512) NULL,
    tls_ok TINYINT(1) NOT NULL DEFAULT 0,
    default_page TINYINT(1) NOT NULL DEFAULT 0,
    error_text TEXT NULL,
    final_url VARCHAR(1024) NULL,
    body_len INT UNSIGNED NOT NULL DEFAULT 0,
    CONSTRAINT fk_scan_http_host FOREIGN KEY (host_id) REFERENCES scan_host (id) ON DELETE CASCADE,
    UNIQUE KEY uq_scan_http_host (host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
