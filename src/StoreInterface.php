<?php

namespace Portier\Client;

/**
 * Interface for stores used by the client.
 */
interface StoreInterface
{
    /**
     * Fetch JSON from cache or using HTTP GET.
     *
     * @param string $cacheId the cache ID to use for this request
     * @param string $url     the URL to fetch of the ID is not available
     *
     * @return \stdClass the JSON object from the response body
     */
    public function fetchCached(string $cacheId, string $url): \stdClass;

    /**
     * Generate and store a nonce.
     *
     * @param string $email email address to associate with the nonce
     *
     * @return string the generated nonce
     */
    public function createNonce(string $email): string;

    /**
     * Consume a nonce, and check if it's valid for the given email address.
     *
     * @param string $nonce the nonce to resolve
     * @param string $email the email address that is being verified
     */
    public function consumeNonce(string $nonce, string $email): void;
}
