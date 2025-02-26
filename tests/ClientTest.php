<?php

namespace Tests;

use Portier\Client;

class ClientTest extends \PHPUnit\Framework\TestCase
{
    public function testNormalize()
    {
        $valid = [
            ['example.foo+bar@example.com', 'example.foo+bar@example.com'],
            ['EXAMPLE.FOO+BAR@EXAMPLE.COM', 'example.foo+bar@example.com'],
            // Simple case transformation
            ['BJÖRN@göteborg.test', 'björn@xn--gteborg-90a.test'],
            // Special case transformation
            ['İⅢ@İⅢ.example', 'i̇ⅲ@xn--iiii-qwc.example'],
        ];
        foreach ($valid as $pair) {
            [$i, $o] = $pair;
            $this->assertEquals(Client\Client::normalize($i), $o);
        }

        $invalid = [
            'foo',
            'foo@',
            '@foo.example',
            'foo@127.0.0.1',
            'foo@[::1]',
        ];
        foreach ($invalid as $i) {
            $this->assertEquals(Client\Client::normalize($i), '');
        }
    }

    public function testAuthenticate()
    {
        $store = new class implements Client\StoreInterface {
            public bool $fetchCachedCalled = false;
            public bool $createNonceCalled = false;

            public function fetchCached(string $cacheId, string $url): \stdClass
            {
                $this->fetchCachedCalled = true;

                return (object) [
                    'authorization_endpoint' => 'http://imaginary-server.test/auth',
                ];
            }

            public function createNonce(string $email): string
            {
                $this->createNonceCalled = true;

                return 'foobar';
            }

            public function consumeNonce(string $nonce, string $email): void
            {
                throw new \Exception('Not implemented');
            }
        };

        $client = new Client\Client($store, 'https://imaginary-client.test/callback');

        $this->assertEquals(
            $client->authenticate('johndoe@example.com', 'dummy state'),
            'http://imaginary-server.test/auth?'.http_build_query([
                'login_hint' => 'johndoe@example.com',
                'scope' => 'openid email',
                'nonce' => 'foobar',
                'response_type' => 'id_token',
                'response_mode' => 'form_post',
                'client_id' => 'https://imaginary-client.test',
                'redirect_uri' => 'https://imaginary-client.test/callback',
                'state' => 'dummy state',
            ])
        );

        $this->assertTrue($store->fetchCachedCalled);
        $this->assertTrue($store->createNonceCalled);
    }

    public function testVerify()
    {
        $this->markTestIncomplete();
    }
}
