<?php
spl_autoload_register(function ($class) {
    // Convert namespace separators to directory separators
    $file = str_replace('\\', DIRECTORY_SEPARATOR, $class);
    
    // Remove 'SafeFingerPrint' from the path since our src directory is the root namespace
    $file = str_replace('SafeFingerPrint' . DIRECTORY_SEPARATOR, '', $file);
    
    $path = __DIR__ . '/src/' . $file . '.php';
    if (file_exists($path)) {
        require_once $path;
    }
});
