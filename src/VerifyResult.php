<?php

namespace Portier\Client;

/** The result of a call to `Client::verify`. */
class VerifyResult
{
    public function __construct(
        /** The verified email address. */
        public string $email,
        /** State that was carry over from the call to `authenticate`. */
        public ?string $state = null,
    ) {
    }
}
