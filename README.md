# SafeFingerPrint Library Documentation

![PHP Version](https://img.shields.io/badge/PHP-%3E%3D7.4-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)


## Introduction 

SafeFingerPrint is a powerful PHP library for advanced visitor tracking, bot detection, and behavior analysis. It provides comprehensive fingerprinting capabilities with sophisticated behavior detection algorithms to help protect your web applications from automated threats while maintaining legitimate user access.

## Table of Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [Security Features](#security-features)
- [Behavior Analysis](#behavior-analysis)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
### Key Features

- Advanced Browser Fingerprinting
- Sophisticated Behavior Analysis
- Bot Detection
- IP Intelligence
- Customizable Security Rules
- Real-time Monitoring
- Detailed Analytics
- Privacy-Compliant Implementation

## Installation

You can install SafeFingerPrint using Composer:

```bash
composer require safefingerprint/core
```

Or by cloning the repository:

```bash
git clone https://github.com/im-syn/SafeFingerPrint.git
cd SafeFingerPrint
composer install
```

### Requirements

Make sure your environment meets these requirements:
- PHP >= 7.4
- ext-json: The JSON extension for PHP
- ext-pdo: The PDO extension for MySQL storage
- Write permissions for the logs directory

### Composer Configuration

The `composer.json` configuration:

```json
{
    "name": "safefingerprint/core",
    "description": "Advanced PHP library for visitor fingerprinting, bot detection, and behavior analysis",
    "type": "library",
    "license": "MIT",
    "authors": [
        {
            "name": "SafeFingerPrint"
        }
    ],
    "minimum-stability": "stable",
    "require": {
        "php": ">=7.4",
        "ext-json": "*",
        "ext-pdo": "*"
    },
    "require-dev": {
        "phpunit/phpunit": "^9.5"
    },
    "autoload": {
        "psr-4": {
            "SafeFingerPrint\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "SafeFingerPrint\\Tests\\": "tests/"
        }
    }
}
```

> 💡 **Tip:** After installation, make sure your web server has write permissions for the logs directory.

## Storage Options

SafeFingerPrint supports multiple storage backends:

1. **JSON File Storage** (default)
   - Stores data in JSON files
   - Simple setup, no database required
   - Good for small to medium sites

2. **MySQL Storage**
   - Stores data in MySQL database
   - Better for high-traffic sites
   - Supports complex queries and analytics

3. **Session Storage**
   - Stores data only in PHP session
   - No persistent storage
   - Perfect for privacy-focused implementations

### Quick Start

Here's a minimal example using JSON storage:

```php
<?php
use SafeFingerPrint\FingerprintTracker;

require_once 'vendor/autoload.php';

$tracker = new FingerprintTracker([
    'storage' => [
        'type' => 'json',
        'json' => [
            'file' => __DIR__ . '/logs/visitors_log.json'
        ]
    ]
]);
$tracker->inject(); // Inject tracking JavaScript
$tracker->handle(); // Handle incoming fingerprint data

// Check if current visitor should be blocked
if ($blockReasons = $tracker->shouldBlock()) {
    header('HTTP/1.0 403 Forbidden');
    exit('Access Denied: ' . implode(', ', $blockReasons));
}
```

## Storage Configuration

### 1. JSON Storage
```php
use SafeFingerPrint\FingerprintTracker;

$tracker = new FingerprintTracker([
    'storage' => [
        'type' => 'json',
        'json' => [
            'file' => __DIR__ . '/logs/visitors_log.json'
        ]
    ]
]);
```

### 2. MySQL Storage
```php
$tracker = new FingerprintTracker([
    'storage' => [
        'type' => 'mysql',
        'mysql' => [
            'host' => 'localhost',
            'database' => 'fingerprints',
            'username' => 'root',
            'password' => 'your_password',
            'table' => 'fingerprints'
        ]
    ]
]);
```

### 3. Session Storage
```php
$tracker = new FingerprintTracker([
    'storage' => [
        'type' => 'session',
        'session' => [
            'key' => 'sfp_session_storage'
        ]
    ]
]);
```

## Configuration

SafeFingerPrint offers extensive configuration options to customize its behavior:

```php
$options = [
    // Storage settings
    'storage' => [
        'type' => 'json', // 'json', 'mysql', or 'session'
        'mysql' => [
            'host' => 'localhost',
            'database' => 'fingerprints',
            'username' => 'root',
            'password' => '',
            'table' => 'fingerprints'
        ],
        'json' => [
            'file' => __DIR__ . '/logs/visitors_log.json'
        ],
        'session' => [
            'key' => 'sfp_session_storage'
        ]
    ],
    
    // Basic settings
    'enableIpInfo' => true,
    'ipInfoTimeout' => 5,
    
    // Cookie settings
    'cookieLifetime' => 86400 * 365,
    'cookiePath' => '/',
    'cookieSecure' => true,
    'cookieHttpOnly' => true,
    'cookieSameSite' => 'Strict',
    
    // Security settings
    'blockTor' => true,
    'blockProxies' => true,
    'blockDatacenters' => false,
    'blockCountries' => ['North Korea', 'Anonymous Proxy'],
    
    // Behavior analysis
    'enableBehaviorScoring' => true,
    'suspiciousClickRate' => 200,
    'suspiciousMoveRate' => 1000,
    'minHumanIdleTime' => 0.2,
    
    // Rate limiting
    'enableRateLimit' => true,
    'rateLimitWindow' => 3600,
    'rateLimitMax' => 100,
];

$tracker = new FingerprintTracker($options);
```

## Basic Usage

### 1. Tracking Visitors

```php
// Initialize tracker
$tracker = new FingerprintTracker([
    'storage' => [
        'type' => 'json',
        'json' => [
            'file' => __DIR__ . '/logs/visitors_log.json'
        ]
    ]
]);

// Add tracking script to your page
$tracker->inject();

// Get current visitor's fingerprint
$fingerprint = $tracker->getFingerprint();

// Get visitor's device information
$deviceInfo = $tracker->getDeviceInfo();

// Check visitor's behavior
$behavior = $tracker->getBehavior();
```

### 2. Security Checks

```php
// Check if visitor should be blocked
$blockReasons = $tracker->shouldBlock();

if (!empty($blockReasons)) {
    // Handle blocked access
    header('HTTP/1.0 403 Forbidden');
    exit('Access Denied: ' . implode(', ', $blockReasons));
}

// Get risk assessment
$ipInfo = $_SESSION['sfp_payload']['ip_info'] ?? [];
$riskScore = 0;

if (!empty($blockReasons)) $riskScore += 40;
if ($ipInfo['is_proxy'] ?? false) $riskScore += 20;
if ($ipInfo['is_tor'] ?? false) $riskScore += 20;
```

## Advanced Features

### Custom Rules

```php
$options = [
    'customRules' => [
        // Custom rule to block specific user agents
        function($record, $data) {
            if (isset($record['device_data']['userAgent'])) {
                if (preg_match('/(bot|crawler)/i', $record['device_data']['userAgent'])) {
                    return 'bot_detected';
                }
            }
            return false;
        },
        // Custom rule for suspicious behavior
        function($record, $data) {
            if (isset($record['behavioral']['clicks']) && 
                $record['behavioral']['clicks'] > 1000) {
                return 'suspicious_activity';
            }
            return false;
        }
    ]
];
```

## Behavior Analysis

SafeFingerPrint includes sophisticated behavior analysis features to detect bots and automated traffic:

```php
$options = [
    'enableBehaviorScoring' => true,
    'mousePatternDetection' => true,
    'keyboardPatternDetection' => true,
    'browserConsistencyCheck' => true,
    'screenBehaviorCheck' => true,
    'interactionQuality' => true,
    
    // Behavior thresholds
    'suspiciousClickRate' => 200,
    'suspiciousMoveRate' => 1000,
    'minHumanIdleTime' => 0.2,
    'maxHumanSpeed' => 1000,
    'minHumanInterval' => 50
];
```

### Behavior Tracking Features

- Mouse movement patterns and velocity
- Click patterns and intervals
- Keyboard input analysis
- Scroll behavior monitoring
- Touch event analysis
- Tab switching patterns
- Copy/paste monitoring
- Text selection patterns

> ⚠️ **Warning:** Be careful when adjusting behavior thresholds. Setting them too strict might affect legitimate users.

## API Reference

### Core Methods

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|-------------|
| `getFingerprint()` | Get current visitor's fingerprint | None | string\|null |
| `getBehavior()` | Get visitor's behavior data | None | array |
| `shouldBlock()` | Check if visitor should be blocked | None | array |
| `getDeviceInfo()` | Get visitor's device information | None | array |
| `getWebRTCIPs()` | Get detected WebRTC IPs | None | array |
| `getStatistics()` | Get tracking statistics | None | array |

## Troubleshooting

### Common Issues and Solutions

1. **High False Positive Rate**
   - If you're getting too many false positives, try:
     - Increasing behavior thresholds
     - Disabling strict mode
     - Adjusting custom rules

2. **Performance Issues**
   - If you experience performance problems:
     - Enable caching
     - Implement log rotation
     - Optimize custom rules

## Storage Best Practices

### Choosing the Right Storage

1. **JSON Storage**
   - Best for: Small to medium websites
   - Advantages:
     - Simple setup
     - No database required
     - Easy to backup and restore
   - Disadvantages:
     - Not suitable for high traffic
     - Limited query capabilities
     - File locking issues possible

2. **MySQL Storage**
   - Best for: High-traffic websites
   - Advantages:
     - Better performance for large datasets
     - Advanced querying capabilities
     - Better concurrent access handling
   - Disadvantages:
     - Requires database setup
     - More complex configuration
     - Additional server resources needed

3. **Session Storage**
   - Best for: Privacy-focused implementations
   - Advantages:
     - No persistent storage
     - Minimal setup required
     - Perfect for GDPR compliance
   - Disadvantages:
     - Data lost after session ends
     - Limited analytics capabilities
     - Not suitable for tracking return visitors

### Implementation Best Practices

1. Start with lenient settings and gradually increase strictness
2. Implement proper error handling and logging
3. Regularly review blocked access logs
4. Keep the library updated
5. Test thoroughly with different user agents and devices
6. Monitor false positive rates
7. Implement whitelisting for known good users
8. Use HTTPS to protect fingerprint data

### Example Implementation with Best Practices

```php
<?php
// Initialize with proper error handling
try {
    $tracker = new FingerprintTracker('logs/visitors_log.json', [
        // Start with lenient settings
        'enableBehaviorScoring' => true,
        'suspiciousClickRate' => 300, // Higher threshold initially
        'suspiciousMoveRate' => 1500, // Higher threshold initially
        'minHumanIdleTime' => 0.1, // More lenient
        
        // Essential security features
        'blockTor' => true,
        'blockProxies' => true,
        
        // Whitelist known good IPs
        'whitelistIPs' => ['192.168.1.100', '10.0.0.50'],
        
        // Log rotation settings
        'logRotation' => 'daily',
        'maxLogSize' => 104857600, // 100MB
        
        // Enable caching for better performance
        'enableCache' => true,
        'cacheDriver' => 'file',
        'cacheExpiration' => 3600
    ]);
    
    // Inject tracking code
    $tracker->inject();
    
    // Handle fingerprint data with logging
    $tracker->handle();
    
    // Comprehensive security check
    $blockReasons = $tracker->shouldBlock();
    $deviceInfo = $tracker->getDeviceInfo();
    $behavior = $tracker->getBehavior();
    
    // Calculate risk score with multiple factors
    $riskScore = calculateRiskScore($blockReasons, $deviceInfo, $behavior);
    
    if ($riskScore >= 70) {
        // Log high-risk access attempts
        error_log("High-risk access attempt: " . json_encode([
            'ip' => $tracker->getIP(),
            'fingerprint' => $tracker->getFingerprint(),
            'risk_score' => $riskScore,
            'reasons' => $blockReasons
        ]));
        
        // Block access
        header('HTTP/1.0 403 Forbidden');
        exit('Access Denied: High-risk activity detected');
    }
    
} catch (Exception $e) {
    // Log errors properly
    error_log("SafeFingerPrint Error: " . $e->getMessage());
    // Fail gracefully
    header('HTTP/1.0 500 Internal Server Error');
    exit('An error occurred');
}

function calculateRiskScore($blockReasons, $deviceInfo, $behavior) {
    $score = 0;
    
    // Basic security checks
    if (!empty($blockReasons)) $score += 40;
    
    // Device consistency checks
    if (empty($deviceInfo['userAgent'])) $score += 10;
    if (preg_match('/(bot|crawler)/i', $deviceInfo['userAgent'] ?? '')) $score += 10;
    
    // Behavior analysis
    if ($behavior['clicks'] > 200) $score += 5;
    if ($behavior['moves'] > 1000) $score += 5;
    if ($behavior['idleSeconds'] < 0.1) $score += 10;
    
    return min(100, $score);
}
```

### Privacy Considerations

> ⚠️ **Legal Consideration:** Ensure your privacy policy includes information about fingerprinting and tracking.

1. Collect only necessary data
2. Implement proper data retention policies
3. Provide clear privacy notices
4. Allow opt-out mechanisms where appropriate
5. Comply with GDPR and other privacy regulations

## Testing

SafeFingerPrint comes with a comprehensive test suite. To run the tests:

```bash
composer install    # Install dependencies including PHPUnit
./vendor/bin/phpunit
```

### Writing Tests

Tests are organized under the `tests/` directory and follow the PSR-4 autoloading standard with the `SafeFingerPrint\Tests` namespace.

Example test:

```php
namespace SafeFingerPrint\Tests;

use PHPUnit\Framework\TestCase;
use SafeFingerPrint\FingerprintTracker;

class FingerprintTrackerTest extends TestCase
{
    private $tracker;
    private $testLogPath;

    protected function setUp(): void
    {
        $this->testLogPath = __DIR__ . '/test_logs/visitors_log.json';
        @mkdir(dirname($this->testLogPath), 0777, true);
        
        $this->tracker = new FingerprintTracker([
            'storage' => [
                'type' => 'json',
                'json' => [
                    'file' => $this->testLogPath
                ]
            ]
        ]);
    }

    public function testCanGetFingerprint()
    {
        $fingerprint = $this->tracker->getFingerprint();
        $this->assertNull($fingerprint); // Initially null before JavaScript runs
    }
}
```

### Test Coverage

The test suite covers:
- Core functionality
- Storage implementations
- Security features
- Behavior analysis
- Edge cases and error handling
