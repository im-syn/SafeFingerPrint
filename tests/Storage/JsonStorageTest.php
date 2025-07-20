<?php

namespace SafeFingerPrint\Tests\Storage;

use PHPUnit\Framework\TestCase;
use SafeFingerPrint\Storage\JsonStorage;

class JsonStorageTest extends TestCase
{
    private $storage;
    private $testFile;

    protected function setUp(): void
    {
        $this->testFile = __DIR__ . '/../test_logs/test_storage.json';
        @mkdir(dirname($this->testFile), 0777, true);
        $this->storage = new JsonStorage($this->testFile);
    }

    protected function tearDown(): void
    {
        @unlink($this->testFile);
        @rmdir(dirname($this->testFile));
    }

    public function testCanSaveAndRetrieveRecord()
    {
        $record = [
            'fingerprint' => 'test123',
            'ip' => '127.0.0.1',
            'timestamp' => date('Y-m-d H:i:s')
        ];

        $this->assertTrue($this->storage->save($record));
        
        $records = $this->storage->getAll();
        $this->assertCount(1, $records);
        $this->assertEquals($record['fingerprint'], $records[0]['fingerprint']);
    }

    public function testCanFindByRecord()
    {
        $record1 = ['fingerprint' => 'test1', 'country' => 'US'];
        $record2 = ['fingerprint' => 'test2', 'country' => 'UK'];
        
        $this->storage->save($record1);
        $this->storage->save($record2);

        $results = $this->storage->findBy(['country' => 'US']);
        $this->assertCount(1, $results);
        $this->assertEquals('test1', $results[0]['fingerprint']);
    }
}
