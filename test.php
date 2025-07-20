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


echo $tracker->getFingerprint();
