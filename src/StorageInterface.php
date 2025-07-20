<?php

interface StorageInterface {
    public function save(array $record): bool;
    public function getAll(): array;
    public function findBy(array $criteria): array;
    public function getStats(): array;
    public function purgeOld(int $olderThan): bool;
}
