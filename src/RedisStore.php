<?php

namespace Portier\Client;

/**
 * A store implementation that uses Redis as the backend.
 */
class RedisStore extends AbstractStore
{
    public \Redis $redis;

    /**
     * Constructor
     * @param \Redis $redis  The Redis instance to use.
     */
    public function __construct(\Redis $redis)
    {
        parent::__construct();

        $this->redis = $redis;
    }

    /**
     * {@inheritDoc}
     */
    public function fetchCached(string $cacheId, string $url): \stdClass
    {
        $key = 'cache:' . $cacheId;

        $data = $this->redis->get($key);
        if ($data) {
            return json_decode($data);
        }

        $res = $this->fetch($url);

        $encoded = json_encode($res->data);
        if ($encoded === false) {
            throw new \Exception('JSON encoding failed');
        }

        $this->redis->setex($key, $res->ttl, $encoded);

        return $res->data;
    }

    /**
     * {@inheritDoc}
     */
    public function createNonce(string $email): string
    {
        $nonce = $this->generateNonce($email);

        $key = 'nonce:' . $nonce;
        $this->redis->setex($key, (int) $this->nonceTtl, $email);

        return $nonce;
    }

    /**
     * {@inheritDoc}
     */
    public function consumeNonce(string $nonce, string $email): void
    {
        $key = 'nonce:' . $nonce;
        $res = $this->redis->multi()
            ->get($key)
            ->del($key)
            ->exec();
        if ($res[0] !== $email) {
            throw new \Exception('Invalid or expired nonce');
        }
    }
}
