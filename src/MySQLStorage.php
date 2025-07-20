<?php

class MySQLStorage implements StorageInterface {
    private $pdo;
    private $table;
    
    public function __construct(array $config) {
        $dsn = "mysql:host={$config['host']};dbname={$config['database']};charset=utf8mb4";
        $this->pdo = new PDO($dsn, $config['username'], $config['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
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
    
    public function save(array $record): bool {
        $sql = "INSERT INTO {$this->table} (
            timestamp, fingerprint, cookie_id, ip, ip_info, device_data, 
            behavioral, webrtc_ips, headers
        ) VALUES (
            :timestamp, :fingerprint, :cookie_id, :ip, :ip_info, :device_data,
            :behavioral, :webrtc_ips, :headers
        )";
        
        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute([
            'timestamp' => $record['timestamp'],
            'fingerprint' => $record['fingerprint'],
            'cookie_id' => $record['cookie_id'],
            'ip' => $record['ip'],
            'ip_info' => json_encode($record['ip_info']),
            'device_data' => json_encode($record['device_data']),
            'behavioral' => json_encode($record['behavioral']),
            'webrtc_ips' => json_encode($record['webrtc_ips']),
            'headers' => json_encode($record['headers'])
        ]);
    }
    
    public function getAll(): array {
        $stmt = $this->pdo->query("SELECT * FROM {$this->table}");
        $records = $stmt->fetchAll();
        return array_map([$this, 'decodeJsonFields'], $records);
    }
    
    public function findBy(array $criteria): array {
        $where = [];
        $params = [];
        foreach ($criteria as $key => $value) {
            $where[] = "$key = :$key";
            $params[$key] = $value;
        }
        
        $sql = "SELECT * FROM {$this->table}";
        if (!empty($where)) {
            $sql .= " WHERE " . implode(" AND ", $where);
        }
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $records = $stmt->fetchAll();
        return array_map([$this, 'decodeJsonFields'], $records);
    }
    
    public function getStats(): array {
        $stats = [
            'total_visits' => $this->pdo->query("SELECT COUNT(*) FROM {$this->table}")->fetchColumn(),
            'unique_fingerprints' => $this->pdo->query("SELECT COUNT(DISTINCT fingerprint) FROM {$this->table}")->fetchColumn(),
            'unique_ips' => $this->pdo->query("SELECT COUNT(DISTINCT ip) FROM {$this->table}")->fetchColumn(),
            'countries' => $this->pdo->query("SELECT DISTINCT JSON_UNQUOTE(JSON_EXTRACT(ip_info, '$.country')) as country FROM {$this->table}")->fetchAll(PDO::FETCH_COLUMN)
        ];
        return $stats;
    }
    
    public function purgeOld(int $olderThan): bool {
        $sql = "DELETE FROM {$this->table} WHERE timestamp < :threshold";
        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute(['threshold' => date('Y-m-d H:i:s', time() - $olderThan)]);
    }
    
    private function decodeJsonFields(array $record): array {
        $jsonFields = ['ip_info', 'device_data', 'behavioral', 'webrtc_ips', 'headers'];
        foreach ($jsonFields as $field) {
            if (isset($record[$field])) {
                $record[$field] = json_decode($record[$field], true);
            }
        }
        return $record;
    }
}
