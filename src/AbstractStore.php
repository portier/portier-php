<?php

namespace Portier\Client;

/**
 * An abstract base class for stores.
 *
 * Offers default implementations for fetching and generating nonces.
 */
abstract class AbstractStore implements StoreInterface
{
    /**
     * The Guzzle instance to use.
     *
     * @var \GuzzleHttp\Client
     */
    public $guzzle;

    /**
     * Lifespan of a nonce.
     *
     * @var int
     */
    public $nonceTtl = 15 * 60;

    /**
     * Minimum time to cache a HTTP response.
     *
     * @var int
     */
    public $cacheMinTtl = 60 * 60;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->guzzle = new \GuzzleHttp\Client([
            'timeout' => 10,
        ]);
    }

    /**
     * Generate a nonce value.
     *
     * @param string $email Optional email context
     *
     * @return string the generated nonce
     */
    public function generateNonce(string $email): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Fetch a URL using HTTP GET.
     *
     * @param string $url the URL to fetch
     *
     * @return object{data: \stdClass, ttl: int}
     */
    public function fetch(string $url): object
    {
        $res = $this->guzzle->get($url);

        $data = json_decode($res->getBody());
        if (!($data instanceof \stdClass)) {
            throw new \Exception('Invalid response body');
        }

        $ttl = 0;
        if ($res->hasHeader('Cache-Control')) {
            if (preg_match(
                '/max-age\s*=\s*(\d+)/',
                $res->getHeaderLine('Cache-Control'),
                $matches
            )) {
                $ttl = intval($matches[1]);
            }
        }
        $ttl = max($this->cacheMinTtl, $ttl);

        return (object) [
            'ttl' => $ttl,
            'data' => $data,
        ];
    }
}
