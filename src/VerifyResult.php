<?php

namespace Portier\Client;

/** The result of a call to `Client::verify`. */
final class VerifyResult
{
    /** The verified email address. */
    public string $email;
    /** State that was carry over from the call to `authenticate`. */
    public ?string $state;

    /** @internal */
    public function __construct(string $email, ?string $state)
    {
        $this->email = $email;
        $this->state = $state;
    }
}
