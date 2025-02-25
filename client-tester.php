#!/usr/bin/env php
<?php

$argv = $_SERVER['argv'];
if (2 !== count($argv)) {
    error_log('Broker required');
    exit(1);
}

require_once __DIR__.'/vendor/autoload.php';

$store = new Portier\Client\MemoryStore();
$client = new Portier\Client\Client($store, 'http://imaginary-client.test/fake-verify-route');
$client->broker = $argv[1];

$stdin = fopen('php://stdin', 'r');
while (($line = fgets($stdin, 4096)) !== false) {
    $cmd = explode("\t", trim($line));
    switch ($cmd[0]) {
        case 'echo':
            echo "ok\t{$cmd[1]}\n";
            break;
        case 'auth':
            try {
                $authUrl = $client->authenticate($cmd[1], $cmd[2] ?? '');
                echo "ok\t{$authUrl}\n";
            } catch (Throwable $err) {
                $msg = implode('  ', explode("\n", $err->getMessage()));
                echo "err\t{$msg}\n";
            }
            break;
        case 'verify':
            try {
                $email = $client->verify($cmd[1]);
                echo "ok\t{$email}\n";
            } catch (Throwable $err) {
                $msg = implode('  ', explode("\n", $err->getMessage()));
                echo "err\t{$msg}\n";
            }
            break;
        case 'clear-cache':
            $store->clearCache();
            echo "ok\n";
            break;
        default:
            error_log("invalid command: {$cmd[0]}");
            exit(1);
    }
}
if (!feof($stdin)) {
    exit(1);
}
