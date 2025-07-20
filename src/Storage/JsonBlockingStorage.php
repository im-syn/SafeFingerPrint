<?php

namespace SafeFingerPrint\Storage;

class JsonBlockingStorage extends JsonStorage {
    public function __construct(string $logPath) {
        parent::__construct(dirname($logPath) . '/blocked_access.json');
    }
}
