<?php

namespace Portier\Client;

/**
 * JWK utility functions.
 */
final class JWK
{
    private function __construct()
    {
    }

    public static function toPem(\stdClass $jwk): string
    {
        if (!isset($jwk->kty) || !is_string($jwk->kty)) {
            throw new \Exception('Missing or invalid kty');
        }

        switch ($jwk->kty) {
            case 'RSA':
                return self::rsaToPem($jwk);
            default:
                throw new \Exception('Unsupported kty: '.substr($jwk->kty, 0, 10));
        }
    }

    private static function rsaToPem(\stdClass $jwk): string
    {
        if (!isset($jwk->n) || !is_string($jwk->n)
            || !isset($jwk->e) || !is_string($jwk->e)) {
            throw new \Exception('Incomplete RSA public jwk');
        }

        $n = DER::encodeValue(DER::ID_INTEGER, self::decodeBase64Url($jwk->n));
        $e = DER::encodeValue(DER::ID_INTEGER, self::decodeBase64Url($jwk->e));
        $body = DER::encodeSequence($n, $e);

        $oid = DER::encodeOid(42, 840, 113549, 1, 1, 1); // RSA
        $header = DER::encodeSequence($oid, DER::NULL);
        $body = DER::encodeBitString($body);
        $key = DER::encodeSequence($header, $body);

        return
            "-----BEGIN PUBLIC KEY-----\n".
            chunk_split(base64_encode($key), 64, "\n").
            "-----END PUBLIC KEY-----\n"
        ;
    }

    private static function decodeBase64Url(string $input): string
    {
        $output = base64_decode(strtr($input, '-_', '+/'), true);
        if (false === $output) {
            throw new \Exception('Invalid base64');
        }

        return $output;
    }
}
