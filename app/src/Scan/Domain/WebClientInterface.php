<?php

declare(strict_types=1);

namespace App\Scan\Domain;

interface WebClientInterface
{
    /**
     * @return list<string>
     */
    public function certificateNames(string $domain): array;

    /**
     * @return list<string>
     */
    public function certspotterNames(string $domain): array;

    /**
     * @return list<string>
     */
    public function waybackNames(string $domain): array;

    /**
     * @return list<string>
     */
    public function hostsearchNames(string $domain): array;

    /**
     * @return list<string>
     */
    public function reverseIpNames(string $ip): array;
}
