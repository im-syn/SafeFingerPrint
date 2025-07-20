<?php

namespace SafeFingerPrint\Storage;

class JsonStorage implements StorageInterface {
    private $filePath;
    
    public function __construct(string $filePath) {
        $this->filePath = $filePath;
        if (!file_exists(dirname($filePath))) {
            mkdir(dirname($filePath), 0777, true);
        }
    }
    
    public function save(array $record): bool {
        $records = $this->getAll();
        $records[] = $record;
        return file_put_contents($this->filePath, json_encode($records, JSON_PRETTY_PRINT)) !== false;
    }
    
    public function getAll(): array {
        if (!file_exists($this->filePath)) {
            return [];
        }
        $content = file_get_contents($this->filePath);
        return $content ? json_decode($content, true) : [];
    }
    
    public function findBy(array $criteria): array {
        $records = $this->getAll();
        return array_filter($records, function($record) use ($criteria) {
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
        $stats = [
            'total_visits' => count($records),
            'unique_fingerprints' => count(array_unique(array_column($records, 'fingerprint'))),
            'unique_ips' => count(array_unique(array_column($records, 'ip'))),
            'countries' => array_unique(array_map(function($record) {
                return $record['ip_info']['country'] ?? 'Unknown';
            }, $records))
        ];
        return $stats;
    }
    
    public function purgeOld(int $olderThan): bool {
        $records = $this->getAll();
        $records = array_filter($records, function($record) use ($olderThan) {
            return strtotime($record['timestamp']) > (time() - $olderThan);
        });
        return file_put_contents($this->filePath, json_encode($records, JSON_PRETTY_PRINT)) !== false;
    }
}
