<?php

namespace SafeFingerPrint\Storage;

class MySQLStorage implements StorageInterface {
    private $pdo;
    private $table;
    
    public function __construct(array $config) {
        $dsn = "mysql:host={$config['host']};dbname={$config['database']};charset=utf8mb4";
        $this->pdo = new \PDO($dsn, $config['username'], $config['password'], [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC
        ]);
        $this->table = $config['table'] ?? 'fingerprints';
        $this->initTable();
    }
    
    private function initTable(): void {
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME,
            fingerprint VARCHAR(64),
            cookie_id VARCHAR(64),
            ip VARCHAR(45),
            ip_info JSON,
            device_data JSON,
            behavioral JSON,
            webrtc_ips JSON,
            headers JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        $this->pdo->exec($sql);
    }
    
    // Rest of the methods remain the same, just update PDO namespace references
}
