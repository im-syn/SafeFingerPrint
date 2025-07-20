<?php

namespace SafeFingerPrint\Storage;

class SessionStorage implements StorageInterface {
    private $sessionKey;
    
    public function __construct(string $sessionKey = 'sfp_session_storage') {
        $this->sessionKey = $sessionKey;
        if (!isset($_SESSION[$this->sessionKey])) {
            $_SESSION[$this->sessionKey] = [];
        }
    }
    
    public function save(array $record): bool {
        $_SESSION[$this->sessionKey][] = $record;
        return true;
    }
    
    public function getAll(): array {
        return $_SESSION[$this->sessionKey] ?? [];
    }
    
    public function findBy(array $criteria): array {
        return array_filter($this->getAll(), function($record) use ($criteria) {
            foreach ($criteria as $key => $value) {
                if (!isset($record[$key]) || $record[$key] !== $value) {
                    return false;
                }
            }
            return true;
        });
    }
    
    public function getStats(): array {
        $records = $this->getAll();
        return [
            'total_visits' => count($records),
            'unique_fingerprints' => count(array_unique(array_column($records, 'fingerprint'))),
            'unique_ips' => count(array_unique(array_column($records, 'ip'))),
            'countries' => array_unique(array_map(function($record) {
                return $record['ip_info']['country'] ?? 'Unknown';
            }, $records))
        ];
    }
    
    public function purgeOld(int $olderThan): bool {
        $records = array_filter($this->getAll(), function($record) use ($olderThan) {
            return strtotime($record['timestamp']) > (time() - $olderThan);
        });
        $_SESSION[$this->sessionKey] = $records;
        return true;
    }
}
