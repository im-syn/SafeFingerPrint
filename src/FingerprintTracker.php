<?php

namespace SafeFingerPrint;

use SafeFingerPrint\Storage\StorageInterface;
use SafeFingerPrint\Storage\JsonStorage;
use SafeFingerPrint\Storage\JsonBlockingStorage;
use SafeFingerPrint\Storage\MySQLStorage;
use SafeFingerPrint\Storage\SessionStorage;

class FingerprintTracker {
    private $storage;
    private $data = [];
    private $currentRecord = null;
    private $options = [
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
                'file' => __DIR__ . '/../logs/visitors_log.json'
            ],
            'session' => [
                'key' => 'sfp_session_storage'
            ]
        ],
        // Basic settings
        'enableIpInfo' => true,
        'ipInfoTimeout' => 5,
        'logFormat' => 'json',
        
        // Cookie settings
        'cookieLifetime' => 86400 * 365,
        'cookiePath' => '/',
        'cookieSecure' => false,
        'cookieHttpOnly' => true,
        'cookieSameSite' => 'Strict',
        
        // Security settings
        'maxVisitsPerHour' => 100,
        'maxVisitsPerDay' => 1000,
        'blockTor' => false,
        'blockProxies' => false,
        'blockDatacenters' => false,
        'blockCountries' => [],
        'whitelistIPs' => [],
        'blacklistIPs' => [],
        'whitelistFingerprints' => [],
        'blacklistFingerprints' => [],
        
        // Rate limiting
        'enableRateLimit' => true,
        'rateLimitWindow' => 3600,
        'rateLimitMax' => 100,
        
        // Behavior analysis
        'enableBehaviorScoring' => true,
        'suspiciousClickRate' => 500, // clicks per minute
        'suspiciousMoveRate' => 2000, // moves per minute
        'minHumanIdleTime' => 0.2, // seconds
        'maxHumanSpeed' => 1000, // max pixels per second
        'minHumanInterval' => 50, // minimum ms between events
        'mousePatternDetection' => true, // detect suspicious mouse patterns
        'keyboardPatternDetection' => true, // detect suspicious keyboard patterns
        'browserConsistencyCheck' => true, // check if browser features are consistent
        'screenBehaviorCheck' => true, // check if screen behavior is human-like
        'interactionQuality' => true, // analyze quality of interactions
        
        // Notification settings
        'enableNotifications' => false,
        'notificationEmail' => '',
        'notificationThreshold' => 'high', // low, medium, high
        'notificationWebhook' => '',
        
        // Logging settings
        'logLevel' => 'info', // debug, info, warning, error
        'logRotation' => 'daily', // hourly, daily, weekly, monthly
        'maxLogSize' => 104857600, // 100MB
        
        // Cache settings
        'enableCache' => true,
        'cacheDriver' => 'file', // file, redis, memcached
        'cacheExpiration' => 3600,
        
        // Custom rules
        'customRules' => []
    ];

    public function __construct(array $options = []) {
        $this->options = array_merge($this->options, $options);
        
        // Initialize storage
        $storageConfig = $this->options['storage'];
        switch ($storageConfig['type']) {
            case 'mysql':
                $this->storage = new MySQLStorage($storageConfig['mysql']);
                break;
            case 'session':
                $this->storage = new SessionStorage($storageConfig['session']['key']);
                break;
            case 'json':
            default:
                $this->storage = new JsonStorage($storageConfig['json']['file']);
                break;
        }
        
        // Load existing session data if available
        if (isset($_SESSION['sfp_payload'])) {
            $this->data = $_SESSION['sfp_payload'];
            $this->currentRecord = [
                'fingerprint' => $_SESSION['sfp_payload']['fingerprint'] ?? null,
                'device_data' => $_SESSION['sfp_payload']['deviceData'] ?? [],
                'behavioral' => $_SESSION['sfp_payload']['behavior'] ?? [],
                'webrtc_ips' => $_SESSION['sfp_payload']['webrtc'] ?? [],
                'headers' => $_SESSION['sfp_payload']['headers'] ?? []
            ];
        }
    }

    /**
     * Check if current visitor matches a specific fingerprint
     */
    public function matchesFingerprint($fingerprint): bool {
        return $this->getFingerprint() === $fingerprint;
    }

    /**
     * Get all stored records for analysis
     */
    public function getStoredRecords(): array {
        return $this->storage->getAll();
    }

    /**
     * Search for records by any field
     */
    public function findRecords(array $criteria): array {
        return $this->storage->findBy($criteria);
    }

    /**
     * Deep match helper for nested arrays
     */
    private function deepMatch($array, $key, $value): bool {
        if (isset($array[$key])) {
            return $array[$key] === $value;
        }
        
        foreach ($array as $k => $v) {
            if (is_array($v) && $this->deepMatch($v, $key, $value)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get statistics about stored fingerprints
     */
    public function getStatistics(): array {
        $records = $this->getStoredRecords();
        $stats = [
            'total_visits' => count($records),
            'unique_fingerprints' => count(array_unique(array_column($records, 'fingerprint'))),
            'unique_ips' => count(array_unique(array_column($records, 'ip_info.ip'))),
            'countries' => [],
            'browsers' => [],
            'platforms' => []
        ];

        foreach ($records as $record) {
            $country = $record['ip_info']['country'] ?? 'Unknown';
            $stats['countries'][$country] = ($stats['countries'][$country] ?? 0) + 1;
            
            if (isset($record['device_data']['userAgent'])) {
                $ua = $record['device_data']['userAgent'];
                if (preg_match('/Chrome|Firefox|Safari|Edge|Opera|MSIE|Trident/i', $ua, $matches)) {
                    $browser = strtolower($matches[0]);
                    $stats['browsers'][$browser] = ($stats['browsers'][$browser] ?? 0) + 1;
                }
                
                if (preg_match('/Windows|Mac|Linux|iOS|Android/i', $ua, $matches)) {
                    $platform = strtolower($matches[0]);
                    $stats['platforms'][$platform] = ($stats['platforms'][$platform] ?? 0) + 1;
                }
            }
        }

        return $stats;
    }

    public function inject() {
        echo '<script>' . $this->getJS() . '</script>';
    }

    public function handle() {
        // Check if it's an API request
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_GET['log'] ?? '') === '1') {
            // Enforce rate limiting and security checks
            $this->enforceAccessControl();
            $data = json_decode(file_get_contents("php://input"), true);
            $cookieId = $_COOKIE['trace_id'] ?? uniqid('trace_', true);
            setcookie('trace_id', $cookieId, time() + (86400 * 365), '/');

            $ip = $_SERVER['REMOTE_ADDR'] ?? 'N/A';
            $fingerprint = $data['fingerprint'] ?? 'N/A';
            $deviceData = $data['deviceData'] ?? [];
            $behavior = $data['behavior'] ?? [];
            $webrtcIPs = $data['webrtc'] ?? [];

            $ipinfo = @json_decode(file_get_contents("https://ipapi.co/{$ip}/json/"), true);

            $record = [
                'timestamp' => date("Y-m-d H:i:s"),
                'fingerprint' => $fingerprint,
                'cookie_id' => $cookieId,
                'ip_info' => [
                    'ip' => $ip,
                    'city' => $ipinfo['city'] ?? 'N/A',
                    'region' => $ipinfo['region'] ?? 'N/A',
                    'country' => $ipinfo['country_name'] ?? 'N/A',
                    'org' => $ipinfo['org'] ?? 'N/A',
                    'is_tor' => $ipinfo['tor'] ?? false,
                    'is_proxy' => $ipinfo['proxy'] ?? false,
                    'is_hosting' => $ipinfo['hosting'] ?? false,
                ],
                'device_data' => $deviceData,
                'behavioral' => $behavior,
                'webrtc_ips' => $webrtcIPs,
                'headers' => getallheaders()
            ];
            
            // Store current record in session and class property
            $_SESSION['sfp_payload'] = [
                'fingerprint' => $fingerprint,
                'deviceData' => $deviceData,
                'behavior' => $behavior,
                'webrtc' => $webrtcIPs,
                'headers' => getallheaders(),
                'ip' => $ip,
                'start_time' => date('Y-m-d H:i:s')
            ];
            $this->currentRecord = $record;
            $this->data = array_merge(['ip' => $ip], $record);

            // Save record to storage
            $this->storage->save($record);

            echo json_encode(['status' => 'logged', 'trace_id' => $cookieId]);
            exit;
        }
    }
    public function getIP(): string {
        return $_SERVER['REMOTE_ADDR'] ?? $this->data['ip'] ?? 'N/A';
    }

    public function getFingerprint(): ?string {
        return $this->currentRecord['fingerprint'] ?? null;
    }

    public function getDeviceInfo(): array {
        return $this->currentRecord['device_data'] ?? [];
    }

    public function getBehavior(): array {
        return $this->currentRecord['behavioral'] ?? [];
    }

    public function getWebRTCIPs(): array {
        return $this->currentRecord['webrtc_ips'] ?? [];
    }

    public function getHeaders(): array {
        return $this->currentRecord['headers'] ?? [];
    }

    /**
     * Check if the current visitor should be blocked
     */
    public function shouldBlock(): array {
        $reasons = [];
        $ip = $this->getIP();
        $fingerprint = $this->getFingerprint();
        
        // Check IP blacklist/whitelist
        if (!empty($this->options['whitelistIPs']) && !in_array($ip, $this->options['whitelistIPs'])) {
            $reasons[] = 'ip_not_whitelisted';
        }
        if (in_array($ip, $this->options['blacklistIPs'])) {
            $reasons[] = 'ip_blacklisted';
        }

        // Check fingerprint blacklist/whitelist
        if (!empty($this->options['whitelistFingerprints']) && !in_array($fingerprint, $this->options['whitelistFingerprints'])) {
            $reasons[] = 'fingerprint_not_whitelisted';
        }
        if (in_array($fingerprint, $this->options['blacklistFingerprints'])) {
            $reasons[] = 'fingerprint_blacklisted';
        }

        // Check country restrictions
        if (!empty($this->options['blockCountries'])) {
            $ipInfo = $this->currentRecord['ip_info'] ?? [];
            $country = $ipInfo['country'] ?? 'Unknown';
            if (in_array($country, $this->options['blockCountries'])) {
                $reasons[] = 'country_blocked';
            }
        }

        // Check for TOR/Proxy/Datacenter
        $ipInfo = $this->currentRecord['ip_info'] ?? [];
        if ($this->options['blockTor'] && ($ipInfo['is_tor'] ?? false)) {
            $reasons[] = 'tor_network';
        }
        if ($this->options['blockProxies'] && ($ipInfo['is_proxy'] ?? false)) {
            $reasons[] = 'proxy_detected';
        }
        if ($this->options['blockDatacenters'] && ($ipInfo['is_hosting'] ?? false)) {
            $reasons[] = 'datacenter_ip';
        }

        // Check rate limits
        if ($this->options['enableRateLimit']) {
            $visits = $this->getRecentVisits($this->options['rateLimitWindow']);
            if (count($visits) > $this->options['rateLimitMax']) {
                $reasons[] = 'rate_limit_exceeded';
            }
        }

        // Check behavior scoring
        if ($this->options['enableBehaviorScoring']) {
            $behavior = $this->getBehavior();
            
            // Get the start time either from record or session
            $startTime = strtotime($this->currentRecord['timestamp'] ?? $_SESSION['sfp_payload']['start_time'] ?? date('Y-m-d H:i:s'));
            $timeActive = max(1, time() - $startTime); // Ensure we don't divide by zero
            
            // Basic rate calculations
            $clicks = $behavior['clicks'] ?? 0;
            $moves = $behavior['moves'] ?? 0;
            $clickRate = ($timeActive > 0) ? ($clicks / ($timeActive / 60)) : 0;
            $moveRate = ($timeActive > 0) ? ($moves / ($timeActive / 60)) : 0;

            // Analyze mouse movement patterns
            if ($this->options['mousePatternDetection']) {
                $mousePoints = $behavior['mousePoints'] ?? [];
                $velocities = $behavior['moveVelocities'] ?? [];
                
                if (!empty($velocities)) {
                    // Check for unnaturally consistent velocities
                    $velocityStdDev = $this->calculateStdDev($velocities);
                    if ($velocityStdDev < 0.1) {
                        $reasons[] = 'suspicious_movement_pattern';
                    }

                    // Check for impossible speeds
                    $maxVelocity = max($velocities);
                    if ($maxVelocity > $this->options['maxHumanSpeed']) {
                        $reasons[] = 'impossible_movement_speed';
                    }
                }

                // Check for perfectly straight lines or geometric patterns
                if ($this->detectGeometricPatterns($mousePoints)) {
                    $reasons[] = 'geometric_movement_pattern';
                }
            }

            // Analyze click patterns
            $clickPoints = $behavior['clickPoints'] ?? [];
            if (!empty($clickPoints)) {
                // Check for perfectly regular click intervals
                $intervals = $behavior['eventIntervals'] ?? [];
                if (!empty($intervals) && $this->isRegularPattern($intervals)) {
                    $reasons[] = 'regular_click_pattern';
                }

                // Check for clicks exactly at the same coordinates
                if ($this->hasIdenticalCoordinates($clickPoints)) {
                    $reasons[] = 'identical_click_coordinates';
                }
            }

            // Analyze keyboard patterns
            if ($this->options['keyboardPatternDetection']) {
                $keyPatterns = $behavior['keyPressPatterns'] ?? [];
                if (!empty($keyPatterns)) {
                    // Check for inhuman typing speed
                    if ($this->detectInhumanTypingSpeed($keyPatterns)) {
                        $reasons[] = 'inhuman_typing_speed';
                    }

                    // Check for lack of natural typing mistakes
                    $backspaces = $behavior['inputBackspaces'] ?? 0;
                    if (count($keyPatterns) > 50 && $backspaces === 0) {
                        $reasons[] = 'no_typing_mistakes';
                    }
                }
            }

            // Analyze interaction quality
            if ($this->options['interactionQuality']) {
                // Check interaction areas coverage
                $interactionAreas = count($behavior['interactionAreas'] ?? []);
                if ($clicks > 10 && $interactionAreas < 3) {
                    $reasons[] = 'limited_interaction_area';
                }

                // Check for natural scroll behavior
                $scrollPatterns = $behavior['scrollPatterns'] ?? [];
                if (!empty($scrollPatterns) && $this->isUnnatural($scrollPatterns)) {
                    $reasons[] = 'unnatural_scroll_pattern';
                }
            }

            // Check basic rate limits
            if ($clickRate > $this->options['suspiciousClickRate']) {
                $reasons[] = 'suspicious_click_rate';
            }
            if ($moveRate > $this->options['suspiciousMoveRate']) {
                $reasons[] = 'suspicious_move_rate';
            }
            if (($behavior['idleSeconds'] ?? 0) < $this->options['minHumanIdleTime']) {
                $reasons[] = 'no_human_idle';
            }
        }

        // Run custom rules
        foreach ($this->options['customRules'] as $rule) {
            if (is_callable($rule)) {
                try {
                    $result = call_user_func($rule, $this->currentRecord, $this->data);
                    if ($result !== false) {
                        $reasons[] = is_string($result) ? $result : 'custom_rule';
                    }
                } catch (\Throwable $e) {
                    // Log error but continue processing
                    error_log("Error in custom rule: " . $e->getMessage());
                }
            }
        }

        return $reasons;
    }

    /**
     * Block the current visitor if necessary
     */
    public function enforceAccessControl(): void {
        $blockReasons = $this->shouldBlock();
        
        if (!empty($blockReasons)) {
            $this->logBlockedAccess($blockReasons);
            $this->sendNotification($blockReasons);
            $this->blockAccess($blockReasons);
        }
    }

    /**
     * Get visits within a time window
     */
    private function getRecentVisits(int $seconds): array {
        $records = $this->getStoredRecords();
        $threshold = time() - $seconds;
        
        return array_filter($records, function($record) use ($threshold) {
            return strtotime($record['timestamp']) >= $threshold;
        });
    }

    /**
     * Log blocked access attempts
     */
    private function logBlockedAccess(array $reasons): void {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $this->getIP(),
            'fingerprint' => $this->getFingerprint(),
            'reasons' => $reasons,
            'data' => $this->currentRecord
        ];

        // Create a blocking storage of the same type as main storage
        $storageConfig = $this->options['storage'];
        switch ($storageConfig['type']) {
            case 'mysql':
                $blockingStorage = new MySQLStorage(array_merge(
                    $storageConfig['mysql'],
                    ['table' => $storageConfig['mysql']['table'] . '_blocked']
                ));
                break;
            case 'session':
                $blockingStorage = new SessionStorage($storageConfig['session']['key'] . '_blocked');
                break;
            case 'json':
            default:
                $blockingStorage = new JsonBlockingStorage($storageConfig['json']['file']);
                break;
        }
        
        $blockingStorage->save($logEntry);
    }

    /**
     * Send notification about blocked access
     */
    private function sendNotification(array $reasons): void {
        if (!$this->options['enableNotifications']) {
            return;
        }

        $message = [
            'type' => 'access_blocked',
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $this->getIP(),
            'fingerprint' => $this->getFingerprint(),
            'reasons' => $reasons,
            'severity' => $this->calculateSeverity($reasons)
        ];

        // Send email notification
        if (!empty($this->options['notificationEmail'])) {
            // Implement email sending here
        }

        // Send webhook notification
        if (!empty($this->options['notificationWebhook'])) {
            $ch = curl_init($this->options['notificationWebhook']);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($message));
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_exec($ch);
            curl_close($ch);
        }
    }

    /**
     * Calculate severity of blocking reasons
     */
    /**
     * Calculate standard deviation of an array of numbers
     */
    private function calculateStdDev(array $values): float {
        $count = count($values);
        if ($count < 2) {
            return 0.0;
        }
        
        $mean = array_sum($values) / $count;
        $squares = array_map(function($x) use ($mean) {
            return pow($x - $mean, 2);
        }, $values);
        
        return sqrt(array_sum($squares) / ($count - 1));
    }

    /**
     * Detect geometric patterns in mouse movements
     */
    private function detectGeometricPatterns(array $points): bool {
        if (count($points) < 10) {
            return false;
        }

        $straightLineCount = 0;
        $angleCount = [];

        for ($i = 2; $i < count($points); $i++) {
            // Calculate angles between consecutive points
            $angle = $this->calculateAngle(
                $points[$i-2], 
                $points[$i-1], 
                $points[$i]
            );
            
            // Round angle to nearest 15 degrees
            $roundedAngle = round($angle / 15) * 15;
            $angleCount[$roundedAngle] = ($angleCount[$roundedAngle] ?? 0) + 1;

            // Check for straight lines
            if (abs($angle - 180) < 5) {
                $straightLineCount++;
            }
        }

        // Too many straight lines or repeated angles indicate bot behavior
        return $straightLineCount > count($points) * 0.7 || 
               max($angleCount) > count($points) * 0.5;
    }

    /**
     * Calculate angle between three points
     */
    private function calculateAngle(array $p1, array $p2, array $p3): float {
        $angle1 = atan2($p1['y'] - $p2['y'], $p1['x'] - $p2['x']);
        $angle2 = atan2($p3['y'] - $p2['y'], $p3['x'] - $p2['x']);
        $angle = abs($angle1 - $angle2) * 180 / M_PI;
        return $angle > 180 ? 360 - $angle : $angle;
    }

    /**
     * Check if a series of time intervals is too regular
     */
    private function isRegularPattern(array $intervals): bool {
        if (count($intervals) < 5) {
            return false;
        }

        $stdDev = $this->calculateStdDev($intervals);
        $mean = array_sum($intervals) / count($intervals);
        
        // If standard deviation is less than 10% of mean, pattern is too regular
        return $stdDev < ($mean * 0.1);
    }

    /**
     * Check for identical coordinates in click patterns
     */
    private function hasIdenticalCoordinates(array $points): bool {
        $coordinates = [];
        foreach ($points as $point) {
            $coord = "{$point['x']},{$point['y']}";
            $coordinates[$coord] = ($coordinates[$coord] ?? 0) + 1;
            
            // If same coordinate clicked more than 3 times
            if ($coordinates[$coord] > 3) {
                return true;
            }
        }
        return false;
    }

    /**
     * Detect inhuman typing speed
     */
    private function detectInhumanTypingSpeed(array $keyPatterns): bool {
        if (count($keyPatterns) < 10) {
            return false;
        }

        $intervals = [];
        for ($i = 1; $i < count($keyPatterns); $i++) {
            $intervals[] = $keyPatterns[$i]['time'] - $keyPatterns[$i-1]['time'];
        }

        $avgInterval = array_sum($intervals) / count($intervals);
        return $avgInterval < 30; // Less than 30ms between keystrokes
    }

    /**
     * Check if scroll pattern is unnatural
     */
    private function isUnnatural(array $scrollPatterns): bool {
        if (count($scrollPatterns) < 5) {
            return false;
        }

        $intervals = [];
        $distances = [];
        for ($i = 1; $i < count($scrollPatterns); $i++) {
            $intervals[] = $scrollPatterns[$i]['time'] - $scrollPatterns[$i-1]['time'];
            $distances[] = abs($scrollPatterns[$i]['top'] - $scrollPatterns[$i-1]['top']);
        }

        // Check for consistent scroll distances and timing
        $distanceStdDev = $this->calculateStdDev($distances);
        $intervalStdDev = $this->calculateStdDev($intervals);

        return $distanceStdDev < 1 || $intervalStdDev < 10;
    }

    private function calculateSeverity(array $reasons): string {
        $highSeverity = ['ip_blacklisted', 'fingerprint_blacklisted', 'tor_network'];
        $mediumSeverity = ['proxy_detected', 'datacenter_ip', 'rate_limit_exceeded'];
        
        foreach ($reasons as $reason) {
            if (in_array($reason, $highSeverity)) {
                return 'high';
            }
        }
        
        foreach ($reasons as $reason) {
            if (in_array($reason, $mediumSeverity)) {
                return 'medium';
            }
        }
        
        return 'low';
    }

    /**
     * Block access and display message or redirect
     */
    private function blockAccess(array $reasons): void {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'blocked',
            'message' => 'Access denied',
            'reasons' => $reasons
        ]);
        exit;
    }
   public function getJS(): string {
    return <<<'JS'
(async () => {
  const data = {
    // Basic info
    userAgent: navigator.userAgent,
    language: navigator.language,
    languages: JSON.stringify(navigator.languages),
    platform: navigator.platform,
    vendor: navigator.vendor,
    
    // Screen and window metrics
    screenResolution: `${screen.width}x${screen.height}`,
    screenDepth: screen.colorDepth,
    screenOrientation: screen.orientation?.type || 'N/A',
    windowSize: `${window.innerWidth}x${window.innerHeight}`,
    devicePixelRatio: window.devicePixelRatio,
    
    // System capabilities
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: new Date().getTimezoneOffset(),
    deviceMemory: navigator.deviceMemory || 'N/A',
    hardwareConcurrency: navigator.hardwareConcurrency || 'N/A',
    
    // Feature detection
    cookiesEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    touchPoints: navigator.maxTouchPoints,
    
    // GPU info
    gpuVendor: '',
    gpuRenderer: '',
    
    // Canvas fingerprint
    canvasFingerprint: '',
    
    // Audio fingerprint
    audioFingerprint: '',
    
    // Connection info
    connectionType: navigator.connection?.type || 'N/A',
    connectionSpeed: navigator.connection?.effectiveType || 'N/A',
    
    // Battery info
    batteryInfo: 'N/A',
    
    // Installed fonts (sample)
    fontFingerprint: ''
  };

  // GPU and WebGL fingerprinting
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl");
    const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
    data.gpuVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
    data.gpuRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    
    // Additional WebGL parameters
    data.webglParams = {
      antialiasing: gl.getContextAttributes().antialias,
      supportedExtensions: gl.getSupportedExtensions(),
      parameters: {
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE)
      }
    };
  } catch (e) {}

  // Canvas fingerprinting
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = 200;
    canvas.height = 50;

    // Draw background
    ctx.fillStyle = 'rgb(128, 128, 128)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw text
    ctx.fillStyle = 'rgb(255, 0, 0)';
    ctx.font = '18px Arial';
    ctx.fillText('Canvas Fingerprint', 10, 30);

    // Add a shape
    ctx.strokeStyle = 'rgb(0, 255, 0)';
    ctx.beginPath();
    ctx.arc(160, 25, 20, 0, Math.PI * 2);
    ctx.stroke();

    data.canvasFingerprint = canvas.toDataURL();
  } catch (e) {}

  // Audio fingerprinting
  try {
    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = audioContext.createOscillator();
    const analyser = audioContext.createAnalyser();
    const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
    
    oscillator.connect(analyser);
    analyser.connect(scriptProcessor);
    scriptProcessor.connect(audioContext.destination);
    
    const audioFingerprint = [];
    scriptProcessor.onaudioprocess = (e) => {
      const array = new Uint8Array(analyser.frequencyBinCount);
      analyser.getByteFrequencyData(array);
      audioFingerprint.push(array.slice(0, 10));
      
      if (audioFingerprint.length >= 5) {
        data.audioFingerprint = JSON.stringify(audioFingerprint);
        oscillator.stop();
        audioContext.close();
      }
    };
    
    oscillator.start(0);
    setTimeout(() => {
      if (oscillator.stop) oscillator.stop();
      if (audioContext.close) audioContext.close();
    }, 100);
  } catch (e) {}

  // Battery status
  try {
    if (navigator.getBattery) {
      const battery = await navigator.getBattery();
      data.batteryInfo = {
        charging: battery.charging,
        level: battery.level,
        chargingTime: battery.chargingTime,
        dischargingTime: battery.dischargingTime
      };
    }
  } catch (e) {}

  // Font detection
  try {
    const fonts = [
      'Arial', 'Times New Roman', 'Courier New', 'Georgia', 'Verdana',
      'Comic Sans MS', 'Impact', 'Tahoma', 'Trebuchet MS', 'Webdings'
    ];
    
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const baseFont = 'monospace';
    
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    const baseFontWidth = (() => {
      ctx.font = `${testSize} ${baseFont}`;
      return ctx.measureText(testString).width;
    })();
    
    const detected = fonts.filter(font => {
      try {
        ctx.font = `${testSize} ${font}, ${baseFont}`;
        return ctx.measureText(testString).width !== baseFontWidth;
      } catch (e) {
        return false;
      }
    });
    
    data.fontFingerprint = detected.join(',');
  } catch (e) {}

  const fingerprintInput = Object.values(data).join('|');
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(fingerprintInput));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const fingerprint = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  let behavior = {
    moves: 0,
    clicks: 0,
    idleSeconds: 0,
    lastActivity: Date.now(),
    mousePoints: [], // Track mouse movement points
    clickPoints: [], // Track click positions
    moveVelocities: [], // Track mouse velocities
    eventIntervals: [], // Track time between events
    scrollPatterns: [], // Track scroll behavior
    keyPressPatterns: [], // Track keyboard patterns
    interactionAreas: new Set(), // Track areas of interaction
    lastPosition: null,
    touchPoints: [], // Track touch events
    accelerometer: [], // Track device motion if available
    screenInteractions: [], // Track where on screen user interacts
    gestureMetrics: [], // Track complex gestures
    pressurePoints: [], // Track pressure points for touch devices
    contextMenus: 0, // Track right-clicks
    dragEvents: 0, // Track drag operations
    inputBackspaces: 0, // Track correction behavior
    focusBlurEvents: [], // Track tab switching
    timeOnPage: 0,
    copyPasteEvents: 0,
    selectionEvents: [] // Track text selection
  };

  // Track mouse movements with velocity and patterns
  document.addEventListener('mousemove', (e) => {
    const now = Date.now();
    behavior.moves++;
    behavior.lastActivity = now;
    
    const point = { x: e.clientX, y: e.clientY, time: now };
    behavior.mousePoints.push(point);
    
    if (behavior.lastPosition) {
      const dx = e.clientX - behavior.lastPosition.x;
      const dy = e.clientY - behavior.lastPosition.y;
      const dt = now - behavior.lastPosition.time;
      const velocity = Math.sqrt(dx*dx + dy*dy) / dt;
      behavior.moveVelocities.push(velocity);
      
      // Keep only last 100 points
      if (behavior.moveVelocities.length > 100) {
        behavior.moveVelocities.shift();
      }
    }
    
    behavior.lastPosition = point;
    behavior.interactionAreas.add(`${Math.floor(e.clientX/50)},${Math.floor(e.clientY/50)}`);
  });

  // Track click patterns and intervals
  document.addEventListener('click', (e) => {
    const now = Date.now();
    behavior.clicks++;
    behavior.lastActivity = now;
    
    behavior.clickPoints.push({
      x: e.clientX,
      y: e.clientY,
      time: now,
      target: e.target.tagName.toLowerCase()
    });
    
    if (behavior.clickPoints.length > 1) {
      const lastClick = behavior.clickPoints[behavior.clickPoints.length - 2];
      behavior.eventIntervals.push(now - lastClick.time);
    }
  });

  // Track keyboard patterns
  document.addEventListener('keydown', (e) => {
    const now = Date.now();
    behavior.lastActivity = now;
    
    if (e.key === 'Backspace') {
      behavior.inputBackspaces++;
    }
    
    behavior.keyPressPatterns.push({
      key: e.key,
      time: now,
      shift: e.shiftKey,
      ctrl: e.ctrlKey,
      alt: e.altKey
    });
  });

  // Track scroll behavior
  document.addEventListener('scroll', (e) => {
    const now = Date.now();
    behavior.lastActivity = now;
    
    behavior.scrollPatterns.push({
      top: window.scrollY,
      time: now,
      direction: behavior.scrollPatterns.length ? 
        (window.scrollY > behavior.scrollPatterns[behavior.scrollPatterns.length - 1].top ? 'down' : 'up') : 'none'
    });
  });

  // Track touch events for mobile
  document.addEventListener('touchstart', (e) => {
    const now = Date.now();
    behavior.lastActivity = now;
    
    const touch = e.touches[0];
    behavior.touchPoints.push({
      x: touch.clientX,
      y: touch.clientY,
      time: now,
      pressure: touch.force || 0,
      touches: e.touches.length
    });
  });

  // Track focus/blur for tab switching
  document.addEventListener('visibilitychange', () => {
    behavior.focusBlurEvents.push({
      state: document.visibilityState,
      time: Date.now()
    });
  });

  // Track copy/paste events
  document.addEventListener('copy', () => behavior.copyPasteEvents++);
  document.addEventListener('paste', () => behavior.copyPasteEvents++);

  // Track text selection
  document.addEventListener('selectionchange', () => {
    const selection = window.getSelection();
    if (selection.toString().length > 0) {
      behavior.selectionEvents.push({
        length: selection.toString().length,
        time: Date.now()
      });
    }
  });

  // Track context menu (right clicks)
  document.addEventListener('contextmenu', (e) => {
    behavior.contextMenus++;
    behavior.lastActivity = Date.now();
  });

  setInterval(() => {
    behavior.idleSeconds = Math.floor((Date.now() - behavior.lastActivity) / 1000);
  }, 1000);

  let webrtcIPs = [];
  try {
    const pc = new RTCPeerConnection({ iceServers: [] });
    pc.createDataChannel('');
    pc.createOffer().then(offer => pc.setLocalDescription(offer));
    pc.onicecandidate = (e) => {
      if (e.candidate) {
        const match = e.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/);
        if (match && !webrtcIPs.includes(match[1])) {
          webrtcIPs.push(match[1]);
        }
      }
    };
    setTimeout(() => pc.close(), 1500);
  } catch (e) {}

  setTimeout(() => {
    sessionStorage.setItem("sfp_debug_view", JSON.stringify({
      ...data,
      fingerprint,
      behavior,
      webrtcIPs
    }, null, 2));

    fetch("?log=1", {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fingerprint,
        deviceData: data,
        behavior,
        webrtc: webrtcIPs
      })
    });
  }, 2000);
})();
JS;
}

}
