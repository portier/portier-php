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
    /** @var \stdClass[] */
    private $cache;
    /** @var \stdClass[] */
    private $nonces;

    /**
     * Constructor
     */
    public function __construct()
    {
        parent::__construct();

        $this->cache = [];
        $this->nonces = [];
    }

    /**
     * {@inheritDoc}
     */
    public function fetchCached(string $cacheId, string $url): \stdClass
    {
        $item = $this->cache[$cacheId] ?? null;
        if ($item !== null && time() < $item->expires) {
            return $item->data;
        }

        $res = $this->fetch($url);

        $this->cache[$cacheId] = (object) [
            'data' => $res->data,
            'expires' => time() + $res->ttl,
        ];

        return $res->data;
    }

    /**
     * {@inheritDoc}
     */
    public function createNonce(string $email): string
    {
        $nonce = $this->generateNonce($email);

        $this->nonces[$nonce] = (object) [
            'email' => $email,
            'expires' => time() + (int) $this->nonceTtl,
        ];

        return $nonce;
    }

    /**
     * {@inheritDoc}
     */
    public function consumeNonce(string $nonce, string $email): void
    {
        $item = $this->nonces[$nonce] ?? null;
        if ($item !== null) {
            unset($this->nonces[$nonce]);

            if ($item->email === $email && time() < $item->expires) {
                return;
            }
        }

        throw new \Exception('Invalid or expired nonce');
    }
}
