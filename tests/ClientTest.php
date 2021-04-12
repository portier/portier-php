<?php

namespace Tests;

use \Portier\Client;

class ClientTest extends \PHPUnit\Framework\TestCase
{
    use \Prophecy\PhpUnit\ProphecyTrait;

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
            list($i, $o) = $pair;
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
        $store = $this->prophesize(Client\StoreInterface::class);
        $store->createNonce('johndoe@example.com')
            ->willReturn('foobar')
            ->shouldBeCalled();

        $client = new Client\Client(
            $store->reveal(),
            'https://example.com/callback'
        );

        $this->assertEquals(
            $client->authenticate('johndoe@example.com'),
            'https://broker.portier.io/auth?' . http_build_query([
                'login_hint' => 'johndoe@example.com',
                'scope' => 'openid email',
                'nonce' => 'foobar',
                'response_type' => 'id_token',
                'response_mode' => 'form_post',
                'client_id' => 'https://example.com',
                'redirect_uri' => 'https://example.com/callback',
            ])
        );
    }

    public function testVerify()
    {
        $this->markTestIncomplete();
    }
}
