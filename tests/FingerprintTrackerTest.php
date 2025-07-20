<?php

namespace SafeFingerPrint\Tests;

use PHPUnit\Framework\TestCase;
use SafeFingerPrint\FingerprintTracker;
use SafeFingerPrint\Storage\JsonStorage;

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

    protected function tearDown(): void
    {
        // Clean up test files
        @unlink($this->testLogPath);
        @rmdir(dirname($this->testLogPath));
    }

    public function testCanCreateInstance()
    {
        $this->assertInstanceOf(FingerprintTracker::class, $this->tracker);
    }

    public function testCanGetIP()
    {
        $ip = $this->tracker->getIP();
        $this->assertNotEmpty($ip);
    }
}
