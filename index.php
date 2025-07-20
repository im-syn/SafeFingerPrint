<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once __DIR__ . '/autoload.php';

use SafeFingerPrint\FingerprintTracker;

// Initialize tracker with custom options
$tracker = new FingerprintTracker([
    // Storage configuration
    'storage' => [
        'type' => 'json', // Can be 'json', 'mysql', or 'session'
        'json' => [
            'file' => __DIR__ . '/logs/visitors_log.json'
        ]
    ],
    
    // Basic settings
    'enableIpInfo' => true,
    'cookieSecure' => isset($_SERVER['HTTPS']),
    'cookieHttpOnly' => true,
    
    // Security settings
    'enableRateLimit' => true,
    'rateLimitWindow' => 3600,
    'rateLimitMax' => 100,
    'blockTor' => true,
    'blockProxies' => true,
    'blockDatacenters' => false,
    'blockCountries' => ['North Korea', 'Anonymous Proxy'],
    
    // Behavior analysis
    'enableBehaviorScoring' => true,
    'suspiciousClickRate' => 200,
    'suspiciousMoveRate' => 1000,
    
    // Custom rules
    'customRules' => [
        // Example custom rule
        function($record, $data) {
            // Block if user agent contains "bot" or "crawler"
            if (isset($record['device_data']['userAgent'])) {
                if (preg_match('/(bot|crawler)/i', $record['device_data']['userAgent'])) {
                    return 'bot_detected';
                }
            }
            return false;
        }
    ]
]);

// Handle incoming fingerprint data
$tracker->handle();

// Get statistics
$stats = $tracker->getStatistics();

// Get stored records for the current fingerprint if it exists
$currentFingerprint = $tracker->getFingerprint();
$matchingRecords = $currentFingerprint ? $tracker->findRecords(['fingerprint' => $currentFingerprint]) : [];
?>
<!DOCTYPE html>
<html>
<head>
    <title>SafeFingerprint Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .fingerprint-card {
            transition: all 0.3s ease;
        }
        .fingerprint-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .stats-number {
            font-size: 24px;
            font-weight: bold;
            color: #0d6efd;
        }
    </style>
</head>
<body>
    <?php $tracker->inject(); ?>
    
    <div class="container py-5">
        <h1 class="mb-4">SafeFingerprint Demo Dashboard</h1>
        
        <!-- Stats Overview -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card fingerprint-card">
                    <div class="card-body text-center">
                        <h5>Total Visits</h5>
                        <div class="stats-number"><?= $stats['total_visits'] ?></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card fingerprint-card">
                    <div class="card-body text-center">
                        <h5>Unique Visitors</h5>
                        <div class="stats-number"><?= $stats['unique_fingerprints'] ?></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card fingerprint-card">
                    <div class="card-body text-center">
                        <h5>Unique IPs</h5>
                        <div class="stats-number"><?= $stats['unique_ips'] ?></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card fingerprint-card">
                    <div class="card-body text-center">
                        <h5>Countries</h5>
                        <div class="stats-number"><?= count($stats['countries']) ?></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Current Visitor Info -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card fingerprint-card">
                    <div class="card-header">
                        <h5 class="mb-0">Your Fingerprint Profile</h5>
                    </div>
                    <div class="card-body">
                        <dl class="row">
                            <dt class="col-sm-4">IP Address</dt>
                            <dd class="col-sm-8"><?= htmlspecialchars($tracker->getIP()) ?></dd>

                            <dt class="col-sm-4">Fingerprint</dt>
                            <dd class="col-sm-8"><code><?= htmlspecialchars($tracker->getFingerprint() ?? 'Generating...') ?></code></dd>

                            <dt class="col-sm-4">Previous Visits</dt>
                            <dd class="col-sm-8"><?= count($matchingRecords) ?></dd>
                        </dl>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card fingerprint-card">
                    <div class="card-header">
                        <h5 class="mb-0">Device Information</h5>
                    </div>
                    <div class="card-body">
                        <?php $deviceInfo = $tracker->getDeviceInfo(); ?>
                        <dl class="row">
                            <dt class="col-sm-4">Browser</dt>
                            <dd class="col-sm-8"><?= htmlspecialchars($deviceInfo['userAgent'] ?? 'N/A') ?></dd>

                            <dt class="col-sm-4">Platform</dt>
                            <dd class="col-sm-8"><?= htmlspecialchars($deviceInfo['platform'] ?? 'N/A') ?></dd>

                            <dt class="col-sm-4">Screen</dt>
                            <dd class="col-sm-8"><?= htmlspecialchars($deviceInfo['screenResolution'] ?? 'N/A') ?></dd>

                            <dt class="col-sm-4">Timezone</dt>
                            <dd class="col-sm-8"><?= htmlspecialchars($deviceInfo['timezone'] ?? 'N/A') ?></dd>
                        </dl>
                    </div>
                </div>
            </div>
        </div>

        <!-- Behavior and Network -->
        <div class="row">
            <div class="col-md-6">
                <div class="card fingerprint-card">
                    <div class="card-header">
                        <h5 class="mb-0">Behavior Tracking</h5>
                    </div>
                    <div class="card-body">
                        <?php $behavior = $tracker->getBehavior(); ?>
                        <dl class="row">
                            <dt class="col-sm-4">Mouse Moves</dt>
                            <dd class="col-sm-8"><?= htmlspecialchars($behavior['moves'] ?? '0') ?></dd>

                            <dt class="col-sm-4">Clicks</dt>
                            <dd class="col-sm-8"><?= htmlspecialchars($behavior['clicks'] ?? '0') ?></dd>

                            <dt class="col-sm-4">Idle Time</dt>
                            <dd class="col-sm-8"><?= htmlspecialchars($behavior['idleSeconds'] ?? '0') ?> seconds</dd>
                        </dl>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card fingerprint-card">
                    <div class="card-header">
                        <h5 class="mb-0">Network Information</h5>
                    </div>
                    <div class="card-body">
                        <h6>WebRTC IPs Detected:</h6>
                        <ul class="list-unstyled">
                            <?php foreach ($tracker->getWebRTCIPs() as $ip): ?>
                                <li><code><?= htmlspecialchars($ip) ?></code></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Status -->
        <div class="row mt-4">
            <div class="col-12">
                <div class="card fingerprint-card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">Security Assessment</h5>
                    </div>
                    <div class="card-body">
                        <?php
                        $blockReasons = $tracker->shouldBlock();
                        $deviceInfo = $tracker->getDeviceInfo();
                        $ipInfo = $_SESSION['sfp_payload']['ip_info'] ?? [];
                        
                        // Calculate risk score (0-100)
                        $riskScore = 0;
                        if (!empty($blockReasons)) $riskScore += 40;
                        if ($ipInfo['is_proxy'] ?? false) $riskScore += 20;
                        if ($ipInfo['is_tor'] ?? false) $riskScore += 20;
                        if ($ipInfo['is_hosting'] ?? false) $riskScore += 10;
                        if (preg_match('/(bot|crawler)/i', $deviceInfo['userAgent'] ?? '')) $riskScore += 10;
                        
                        // Determine risk level
                        $riskLevel = $riskScore >= 70 ? 'High' : ($riskScore >= 30 ? 'Medium' : 'Low');
                        $riskColor = $riskScore >= 70 ? 'danger' : ($riskScore >= 30 ? 'warning' : 'success');
                        ?>
                        
                        <div class="row align-items-center">
                            <div class="col-md-3 text-center">
                                <h6>Risk Score</h6>
                                <div class="display-4 text-<?= $riskColor ?>"><?= $riskScore ?>%</div>
                                <span class="badge bg-<?= $riskColor ?>"><?= $riskLevel ?> Risk</span>
                            </div>
                            
                            <div class="col-md-9">
                                <h6>Security Flags:</h6>
                                <ul class="list-unstyled">
                                    <?php if (empty($blockReasons)): ?>
                                        <li>✅ No blocking rules triggered</li>
                                    <?php else: ?>
                                        <li>❌ Blocking rules triggered: <?= implode(', ', $blockReasons) ?></li>
                                    <?php endif; ?>
                                    
                                    <li><?= ($ipInfo['is_proxy'] ?? false) ? '❌' : '✅' ?> Proxy Detection</li>
                                    <li><?= ($ipInfo['is_tor'] ?? false) ? '❌' : '✅' ?> TOR Network</li>
                                    <li><?= ($ipInfo['is_hosting'] ?? false) ? '⚠️' : '✅' ?> Datacenter IP</li>
                                    <li><?= preg_match('/(bot|crawler)/i', $deviceInfo['userAgent'] ?? '') ? '❌' : '✅' ?> Bot Detection</li>
                                </ul>
                            </div>
                        </div>

                        <?php if (!empty($blockReasons)): ?>
                            <div class="alert alert-danger mt-3">
                                <strong>Warning:</strong> This visitor would be blocked in production mode.
                                Reasons: <?= implode(', ', $blockReasons) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh the page every 5 seconds to update behavior data
        setTimeout(() => location.reload(), 5000);
    </script>
</body>
</html>
