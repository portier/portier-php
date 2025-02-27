<?php

namespace Portier\Client;

/**
 * A store implementation that uses Redis as the backend.
 */
class RedisStore extends AbstractStore
{
    public \Redis $redis;

    /**
     * Constructor.
     *
     * @param \Redis $redis the Redis instance to use
     */
    public function __construct(\Redis $redis)
    {
        parent::__construct();

        $this->redis = $redis;
    }

    public function fetchCached(string $cacheId, string $url): \stdClass
    {
        $key = 'cache:'.$cacheId;

        $data = $this->redis->get($key);
        if (is_string($data) && $data) {
            $data = json_decode($data);
            assert($data instanceof \stdClass);

            return $data;
        }

        $res = $this->fetch($url);

        $encoded = json_encode($res->data);
        if (false === $encoded) {
            throw new \Exception('JSON encoding failed');
        }

        $this->redis->setex($key, $res->ttl, $encoded);

        return $res->data;
    }

    public function createNonce(string $email): string
    {
        $nonce = $this->generateNonce($email);

        $key = 'nonce:'.$nonce;
        $this->redis->setex($key, (int) $this->nonceTtl, $email);

        return $nonce;
    }

    public function consumeNonce(string $nonce, string $email): void
    {
        $key = 'nonce:'.$nonce;
        $this->redis->multi();
        $this->redis->get($key);
        $this->redis->del($key);
        $res = $this->redis->exec();
        if ($res[0] !== $email) {
            throw new \Exception('Invalid or expired nonce');
        }
    }
}
