<?php

declare(strict_types=1);

namespace App\Scan\Persistence;

use App\Scan\Application\ScanSettings;
use App\Scan\Domain\ScanResult;
use App\Scan\Domain\Target;
use App\Scan\Job\JobContext;
use App\Scan\Job\ScanStage;
use PDO;

final class ScanRepository
{
    public function __construct(
        private readonly PDO $pdo,
    ) {
    }

    public function enqueue(Target $target, ScanSettings $settings): int
    {
        $targetId = $this->findOrCreateTarget($target);
        $stmt = $this->pdo->prepare(
            'INSERT INTO scan_run (
                target_id, status, stage, stage_message,
                dns_threads, http_timeout, probe_http, use_passive, use_reverse_ip, try_axfr
             ) VALUES (
                :target_id, :status, :stage, :stage_message,
                :dns_threads, :http_timeout, :probe_http, :use_passive, :use_reverse_ip, :try_axfr
             )',
        );
        $stmt->execute([
            'target_id' => $targetId,
            'status' => 'queued',
            'stage' => ScanStage::Queued->value,
            'stage_message' => 'waiting for worker',
            'dns_threads' => $settings->dnsThreads,
            'http_timeout' => $settings->httpTimeout,
            'probe_http' => $settings->probeHttp ? 1 : 0,
            'use_passive' => $settings->usePassive ? 1 : 0,
            'use_reverse_ip' => $settings->useReverseIp ? 1 : 0,
            'try_axfr' => $settings->tryAxfr ? 1 : 0,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Atomically claim next unfinished job (queued, or running mid-pipeline).
     *
     * @return array<string, mixed>|null
     */
    public function claimNext(): ?array
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->query(
                "SELECT r.*, t.input AS target_input, t.kind AS target_kind, t.value AS target_value
                 FROM scan_run r
                 INNER JOIN scan_target t ON t.id = r.target_id
                 WHERE r.status IN ('queued', 'running')
                 ORDER BY FIELD(r.status, 'running', 'queued'), r.id ASC
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED",
            );
            $row = $stmt === false ? false : $stmt->fetch();
            if ($row === false) {
                $this->pdo->commit();

                return null;
            }

            return $this->markClaimed($row);
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    public function claimRun(int $runId): ?array
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare(
                "SELECT r.*, t.input AS target_input, t.kind AS target_kind, t.value AS target_value
                 FROM scan_run r
                 INNER JOIN scan_target t ON t.id = r.target_id
                 WHERE r.id = :id AND r.status IN ('queued', 'running')
                 LIMIT 1
                 FOR UPDATE",
            );
            $stmt->execute(['id' => $runId]);
            $row = $stmt->fetch();
            if ($row === false) {
                $this->pdo->commit();

                return null;
            }

            return $this->markClaimed($row);
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    public function saveProgress(
        int $runId,
        ScanStage $nextStage,
        string $message,
        JobContext $ctx,
        string $status = 'running',
    ): void {
        $stmt = $this->pdo->prepare(
            "UPDATE scan_run
             SET status = :status,
                 stage = :stage,
                 stage_message = :stage_message,
                 context_json = :context_json,
                 notes_json = :notes_json,
                 wildcard_ips_json = :wildcard_ips_json,
                 ips_json = :ips_json,
                 names_json = :names_json
             WHERE id = :id",
        );
        $stmt->execute([
            'status' => $status,
            'stage' => $nextStage->value,
            'stage_message' => mb_substr($message, 0, 255),
            'context_json' => $this->json($ctx->toArray()),
            'notes_json' => $this->json($ctx->notes),
            'wildcard_ips_json' => $this->json($ctx->wildcardIps),
            'ips_json' => $this->json($ctx->ips),
            'names_json' => $this->json($ctx->names),
            'id' => $runId,
        ]);
    }

    public function completeRun(int $runId, ScanResult $result, JobContext $ctx): void
    {
        $this->pdo->beginTransaction();
        try {
            $this->pdo->prepare('DELETE FROM scan_host WHERE run_id = :id')->execute(['id' => $runId]);
            $this->pdo->prepare('DELETE FROM scan_dns_record WHERE run_id = :id')->execute(['id' => $runId]);

            $update = $this->pdo->prepare(
                "UPDATE scan_run
                 SET status = 'done',
                     stage = :stage,
                     stage_message = 'completed',
                     context_json = :context_json,
                     wildcard_ips_json = :wildcard_ips_json,
                     notes_json = :notes_json,
                     ips_json = :ips_json,
                     names_json = :names_json,
                     error_text = NULL,
                     finished_at = CURRENT_TIMESTAMP(3)
                 WHERE id = :id",
            );
            $update->execute([
                'stage' => ScanStage::Done->value,
                'context_json' => $this->json($ctx->toArray()),
                'wildcard_ips_json' => $this->json($result->wildcardIps),
                'notes_json' => $this->json($result->notes),
                'ips_json' => $this->json($result->ips),
                'names_json' => $this->json($result->names),
                'id' => $runId,
            ]);

            $this->insertHostsAndRecords($runId, $result);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    public function failRun(int $runId, string $error): void
    {
        $stmt = $this->pdo->prepare(
            "UPDATE scan_run
             SET status = 'failed',
                 stage = :stage,
                 stage_message = 'failed',
                 error_text = :error,
                 finished_at = CURRENT_TIMESTAMP(3)
             WHERE id = :id",
        );
        $stmt->execute([
            'stage' => ScanStage::Failed->value,
            'error' => mb_substr($error, 0, 4000),
            'id' => $runId,
        ]);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function listRuns(int $limit = 50): array
    {
        $limit = max(1, $limit);
        $stmt = $this->pdo->query(
            "SELECT r.id, r.status, r.stage, r.stage_message, r.started_at, r.finished_at,
                    r.probe_http, r.error_text,
                    t.kind AS target_kind, t.value AS target_value, t.input AS target_input,
                    (SELECT COUNT(*) FROM scan_host h WHERE h.run_id = r.id) AS host_count
             FROM scan_run r
             INNER JOIN scan_target t ON t.id = r.target_id
             ORDER BY r.id DESC
             LIMIT {$limit}",
        );

        return $stmt === false ? [] : $stmt->fetchAll();
    }

    /**
     * @return array<string, mixed>|null
     */
    public function findRun(int $id): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT r.*, t.kind AS target_kind, t.value AS target_value, t.input AS target_input
             FROM scan_run r
             INNER JOIN scan_target t ON t.id = r.target_id
             WHERE r.id = :id',
        );
        $stmt->execute(['id' => $id]);
        $run = $stmt->fetch();
        if ($run === false) {
            return null;
        }

        $run['context'] = $this->decodeJson($run['context_json'] ?? null) ?? [];
        foreach (['wildcard_ips_json' => 'wildcard_ips', 'notes_json' => 'notes', 'ips_json' => 'ips', 'names_json' => 'names'] as $from => $to) {
            $run[$to] = $this->decodeJson($run[$from] ?? null) ?? [];
        }

        $hostStmt = $this->pdo->prepare(
            'SELECT * FROM scan_host WHERE run_id = :run_id ORDER BY kind, name',
        );
        $hostStmt->execute(['run_id' => $id]);
        $hosts = $hostStmt->fetchAll();

        $httpStmt = $this->pdo->prepare(
            'SELECT h.* FROM scan_http_check h
             INNER JOIN scan_host sh ON sh.id = h.host_id
             WHERE sh.run_id = :run_id',
        );
        $httpStmt->execute(['run_id' => $id]);
        $httpByHost = [];
        foreach ($httpStmt->fetchAll() as $row) {
            $httpByHost[(int) $row['host_id']] = $row;
        }

        foreach ($hosts as &$host) {
            $host['ips'] = $this->decodeJson($host['ips_json'] ?? null) ?? [];
            $host['cname'] = $this->decodeJson($host['cname_json'] ?? null) ?? [];
            $host['sources'] = $this->decodeJson($host['sources_json'] ?? null) ?? [];
            $host['http'] = $httpByHost[(int) $host['id']] ?? null;
        }
        unset($host);

        // While running, show hosts from context before finalize
        if ($hosts === [] && is_array($run['context']['hosts'] ?? null)) {
            $hosts = $run['context']['hosts'];
        }

        $recordStmt = $this->pdo->prepare(
            'SELECT name, rtype, value FROM scan_dns_record WHERE run_id = :run_id ORDER BY id',
        );
        $recordStmt->execute(['run_id' => $id]);

        $run['hosts'] = $hosts;
        $run['records'] = $recordStmt->fetchAll();

        return $run;
    }

    /**
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     */
    private function markClaimed(array $row): array
    {
        $upd = $this->pdo->prepare(
            "UPDATE scan_run
             SET status = 'running',
                 started_at = COALESCE(started_at, CURRENT_TIMESTAMP(3))
             WHERE id = :id",
        );
        $upd->execute(['id' => (int) $row['id']]);
        $this->pdo->commit();

        $row['status'] = 'running';
        $row['context'] = $this->decodeJson($row['context_json'] ?? null) ?? [];

        return $row;
    }

    private function insertHostsAndRecords(int $runId, ScanResult $result): void
    {
        $hostStmt = $this->pdo->prepare(
            'INSERT INTO scan_host (run_id, name, kind, ips_json, cname_json, sources_json)
             VALUES (:run_id, :name, :kind, :ips_json, :cname_json, :sources_json)',
        );
        $httpStmt = $this->pdo->prepare(
            'INSERT INTO scan_http_check
                (host_id, works, status_code, title, tls_ok, default_page, error_text, final_url, body_len)
             VALUES
                (:host_id, :works, :status_code, :title, :tls_ok, :default_page, :error_text, :final_url, :body_len)',
        );
        $recordStmt = $this->pdo->prepare(
            'INSERT INTO scan_dns_record (run_id, name, rtype, value)
             VALUES (:run_id, :name, :rtype, :value)',
        );

        foreach ($result->hosts as $host) {
            $hostStmt->execute([
                'run_id' => $runId,
                'name' => $host->name,
                'kind' => $host->kind,
                'ips_json' => $this->json($host->ips),
                'cname_json' => $this->json($host->cname),
                'sources_json' => $this->json($host->sources),
            ]);
            $hostId = (int) $this->pdo->lastInsertId();
            if ($host->http !== null) {
                $http = $host->http;
                $httpStmt->execute([
                    'host_id' => $hostId,
                    'works' => $http->works ? 1 : 0,
                    'status_code' => $http->status,
                    'title' => $http->title !== '' ? $http->title : null,
                    'tls_ok' => $http->tlsOk ? 1 : 0,
                    'default_page' => $http->defaultPage ? 1 : 0,
                    'error_text' => $http->error !== '' ? $http->error : null,
                    'final_url' => $http->finalUrl !== '' ? $http->finalUrl : null,
                    'body_len' => $http->bodyLen,
                ]);
            }
        }

        foreach ($result->records as $record) {
            $recordStmt->execute([
                'run_id' => $runId,
                'name' => $record->name,
                'rtype' => $record->rtype,
                'value' => $record->value,
            ]);
        }
    }

    private function findOrCreateTarget(Target $target): int
    {
        $select = $this->pdo->prepare(
            'SELECT id FROM scan_target WHERE kind = :kind AND value = :value LIMIT 1',
        );
        $select->execute([
            'kind' => $target->kind,
            'value' => $target->value,
        ]);
        $existing = $select->fetchColumn();
        if ($existing !== false) {
            return (int) $existing;
        }

        $insert = $this->pdo->prepare(
            'INSERT INTO scan_target (input, kind, value) VALUES (:input, :kind, :value)',
        );
        $insert->execute([
            'input' => $target->raw,
            'kind' => $target->kind,
            'value' => $target->value,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    private function json(mixed $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private function decodeJson(mixed $value): mixed
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_array($value)) {
            return $value;
        }

        return json_decode((string) $value, true);
    }
}
