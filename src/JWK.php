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
            case 'EC':
                return self::ecToPem($jwk);
            case 'OKP':
                return self::okpToPem($jwk);
            default:
                throw new \Exception('Unsupported kty: '.substr($jwk->kty, 0, 10));
        }
    }

    private static function rsaToPem(\stdClass $jwk): string
    {
        if (!isset($jwk->n) || !is_string($jwk->n)
            || !isset($jwk->e) || !is_string($jwk->e)) {
            throw new \Exception('Incomplete RSA public key');
        }

        // RSAPublicKey
        $n = DER::encodeValue(DER::ID_INTEGER, self::decodeBase64Url($jwk->n));
        $e = DER::encodeValue(DER::ID_INTEGER, self::decodeBase64Url($jwk->e));
        $key = DER::encodeSequence($n, $e);

        // PublicKeyInfo
        $oid = DER::encodeOid(42, 840, 113549, 1, 1, 1); // RSA
        $alg = DER::encodeSequence($oid, DER::NULL);
        $key = DER::encodeBitString($key);
        $info = DER::encodeSequence($alg, $key);

        return self::derToPem($info);
    }

    private static function ecToPem(\stdClass $jwk): string
    {
        if (!isset($jwk->crv) || !is_string($jwk->crv)
            || !isset($jwk->x) || !is_string($jwk->x)
            || !isset($jwk->y) || !is_string($jwk->y)) {
            throw new \Exception('Incomplete EC public key');
        }

        $curveOid = null;
        switch ($jwk->crv) {
            case 'P-256':
                $curveOid = [42, 840, 10045, 3, 1, 7];
                break;
            case 'P-384':
                $curveOid = [43, 132, 0, 34];
                break;
            case 'P-521':
                $curveOid = [43, 132, 0, 35];
                break;
            case 'secp256k1':
                $curveOid = [43, 132, 0, 10];
                break;
            default:
                throw new \Exception('Unsupported EC curve: '.substr($jwk->crv, 0, 10));
        }

        // ECPoint
        $x = self::decodeBase64Url($jwk->x);
        $y = self::decodeBase64Url($jwk->y);
        $key = "\x04".$x.$y;

        // PublicKeyInfo
        $oid = DER::encodeOid(42, 840, 10045, 2, 1);
        $curveOid = DER::encodeOid(...$curveOid);
        $alg = DER::encodeSequence($oid, $curveOid);
        $key = DER::encodeBitString($key);
        $info = DER::encodeSequence($alg, $key);

        return self::derToPem($info);
    }

    private static function okpToPem(\stdClass $jwk): string
    {
        if (!isset($jwk->crv) || !is_string($jwk->crv)
            || !isset($jwk->x) || !is_string($jwk->x)) {
            throw new \Exception('Incomplete OKP public key');
        }

        $oid = null;
        switch ($jwk->crv) {
            case 'X25519':
                $oid = [43, 101, 110];
                break;
            case 'X448':
                $oid = [43, 101, 111];
                break;
            case 'Ed25519':
                $oid = [43, 101, 112];
                break;
            case 'X25519':
                $oid = [43, 101, 113];
                break;
            default:
                throw new \Exception('Unsupported OKP curve: '.substr($jwk->crv, 0, 10));
        }

        $key = self::decodeBase64Url($jwk->x);

        // PublicKeyInfo
        $oid = DER::encodeOid(...$oid);
        $alg = DER::encodeSequence($oid);
        $key = DER::encodeBitString($key);
        $info = DER::encodeSequence($alg, $key);

        return self::derToPem($info);
    }

    private static function derToPem(string $der): string
    {
        return
            "-----BEGIN PUBLIC KEY-----\n".
            chunk_split(base64_encode($der), 64, "\n").
            "-----END PUBLIC KEY-----\n";
    }

    /**
     * @internal for tests only
     */
    public static function decodeBase64Url(string $input): string
    {
        $output = base64_decode(strtr($input, '-_', '+/'), true);
        if (false === $output) {
            throw new \Exception('Invalid base64');
        }

        return $output;
    }
}
