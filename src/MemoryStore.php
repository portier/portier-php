<?php

namespace Portier\Client;

/**
 * A store implementation that keeps everything in-memory.
 *
 * This will often not work as expected, because PHP clears everything between
 * requests. It only exists for testing purposes.
 */
class MemoryStore extends AbstractStore
{
    /** @var array<string, object{data: \stdClass, expires: int}> */
    private $cache;
    /** @var array<string, object{clientId: string, email: string, expires: int}> */
    private $nonces;

    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct();

        $this->cache = [];
        $this->nonces = [];
    }

    /**
     * @internal for testing only
     */
    public function clearCache(): void
    {
        $this->cache = [];
    }

    public function fetchCached(string $cacheId, string $url): \stdClass
    {
        $item = $this->cache[$cacheId] ?? null;
        if (null !== $item && time() < $item->expires) {
            return $item->data;
        }

        $res = $this->fetch($url);

        $this->cache[$cacheId] = (object) [
            'data' => $res->data,
            'expires' => time() + $res->ttl,
        ];

        return $res->data;
    }

    public function createNonce(string $clientId, string $email): string
    {
        $nonce = $this->generateNonce($email);

        $this->nonces[$nonce] = (object) [
            'clientId' => $clientId,
            'email' => $email,
            'expires' => time() + (int) $this->nonceTtl,
        ];

        return $nonce;
    }

    public function consumeNonce(string $nonce, string $clientId, string $email): void
    {
        $item = $this->nonces[$nonce] ?? null;
        if (null !== $item) {
            unset($this->nonces[$nonce]);

            if ($item->clientId === $clientId
                && $item->email === $email
                && time() < $item->expires
            ) {
                return;
            }
        }

        throw new \Exception('Invalid or expired nonce');
    }
}
