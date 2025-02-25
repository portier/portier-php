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

    public function createNonce(string $clientId, string $email): string
    {
        $nonce = $this->generateNonce($email);

        $key = 'nonce:'.$nonce;
        $value = (object) ['clientId' => $clientId, 'email' => $email];
        $value = json_encode($value, flags: JSON_THROW_ON_ERROR);
        $this->redis->setex($key, (int) $this->nonceTtl, $value);

        return $nonce;
    }

    public function consumeNonce(string $nonce, string $clientId, string $email): void
    {
        $key = 'nonce:'.$nonce;
        $this->redis->multi();
        $this->redis->get($key);
        $this->redis->del($key);
        [$value] = $this->redis->exec();
        assert(is_string($value));

        // Handle old record that didn't include client ID.
        if (!str_starts_with($value, '{')) {
            if ($value !== $email) {
                throw new \Exception('Invalid or expired nonce');
            }

            return;
        }

        $value = json_decode($value, flags: JSON_THROW_ON_ERROR);
        if (!($value instanceof \stdClass)
            || ($value->email ?? null) !== $email
            || ($value->clientId ?? null) !== $clientId
        ) {
            throw new \Exception('Invalid or expired nonce');
        }
    }
}
