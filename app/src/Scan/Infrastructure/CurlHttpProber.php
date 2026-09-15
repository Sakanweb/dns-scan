<?php

declare(strict_types=1);

namespace App\Scan\Infrastructure;

use App\Scan\Domain\HttpCheck;
use App\Scan\Domain\HttpProberInterface;
use App\Scan\Domain\Parsers;

final class CurlHttpProber implements HttpProberInterface
{
    private const USER_AGENT = 'dns-scan/1.0 (local inventory)';

    public function __construct(
        private readonly int $timeout = 10,
    ) {
    }

    public function probe(string $host): HttpCheck
    {
        $https = $this->fetch("https://{$host}/", true);
        if (str_starts_with($https->error, 'tls:')) {
            $insecure = $this->fetch("https://{$host}/", false);
            $insecure = new HttpCheck(
                $insecure->works,
                $insecure->status,
                $insecure->title,
                $insecure->finalUrl,
                false,
                $insecure->defaultPage,
                $insecure->error,
                $insecure->bodyLen,
            );
            if ($insecure->status !== null) {
                return $insecure;
            }
        }
        if ($https->status !== null) {
            return $https;
        }

        $http = $this->fetch("http://{$host}/", false);

        return new HttpCheck(
            $http->works,
            $http->status,
            $http->title,
            $http->finalUrl,
            false,
            $http->defaultPage,
            $http->error,
            $http->bodyLen,
        );
    }

    private function fetch(string $url, bool $verifyTls): HttpCheck
    {
        if (!function_exists('curl_init')) {
            return new HttpCheck(false, null, '', $url, $verifyTls, false, 'curl extension missing', 0);
        }

        $ch = curl_init($url);
        if ($ch === false) {
            return new HttpCheck(false, null, '', $url, $verifyTls, false, 'curl init failed', 0);
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => $verifyTls,
            CURLOPT_SSL_VERIFYHOST => $verifyTls ? 2 : 0,
            CURLOPT_HEADER => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        ]);

        $raw = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $finalUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        if ($raw === false) {
            $message = $error !== '' ? $error : "curl errno {$errno}";
            if ($this->isTlsError($errno, $message)) {
                return new HttpCheck(false, null, '', $url, false, false, 'tls:' . $message, 0);
            }

            return new HttpCheck(false, null, '', $url, $verifyTls, false, $message, 0);
        }

        $body = substr((string) $raw, 0, 200_000);
        $title = Parsers::htmlTitle($body);
        $default = Parsers::isDefaultPage($title, $body);
        $bodyLen = strlen($body);

        if ($status >= 400) {
            $works = false;
            if ($status < 500 && !in_array($status, [404, 410], true)) {
                $works = true;
            }
            if ($status >= 200 && $status < 400 && !$default) {
                $works = true;
            }

            return new HttpCheck(
                $works,
                $status,
                $title,
                $finalUrl !== '' ? $finalUrl : $url,
                $verifyTls,
                $default,
                '',
                $bodyLen,
            );
        }

        $works = $status >= 200 && $status < 400 && !$default && strlen(trim($body)) > 80;

        return new HttpCheck(
            $works,
            $status > 0 ? $status : 200,
            $title,
            $finalUrl !== '' ? $finalUrl : $url,
            $verifyTls,
            $default,
            '',
            $bodyLen,
        );
    }

    private function isTlsError(int $errno, string $message): bool
    {
        $tlsErrnos = [
            defined('CURLE_SSL_CONNECT_ERROR') ? CURLE_SSL_CONNECT_ERROR : 35,
            defined('CURLE_SSL_CERTPROBLEM') ? CURLE_SSL_CERTPROBLEM : 58,
            defined('CURLE_SSL_CACERT') ? CURLE_SSL_CACERT : 60,
            defined('CURLE_SSL_CACERT_BADFILE') ? CURLE_SSL_CACERT_BADFILE : 77,
            defined('CURLE_SSL_PEER_CERTIFICATE') ? CURLE_SSL_PEER_CERTIFICATE : 51,
        ];
        if (in_array($errno, $tlsErrnos, true)) {
            return true;
        }

        $lower = strtolower($message);

        return str_contains($lower, 'ssl') || str_contains($lower, 'tls') || str_contains($lower, 'certificate');
    }
}
