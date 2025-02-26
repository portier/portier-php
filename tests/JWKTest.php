<?php

namespace Tests;

use Lcobucci\JWT\Signer;
use Portier\Client\JWK;

class JWKTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Maps signing algorithm to fixture basename.
     *
     * These fixtures were all generated using jwx:
     * https://github.com/lestrrat-go/jwx
     *
     * The signed message is simply 'hello'.
     *
     * @todo Test secp256k1
     * @todo Test x25519
     * @todo Test ed448
     * @todo Test x448
     */
    private const FIXTURES = [
        'RS256' => 'rsa',
        'ES256' => 'p256',
        'ES384' => 'p384',
        'ES512' => 'p521',
        'EdDSA' => 'ed25519',
    ];

    /**
     * Tests JWK to PEM conversion by using the PEM result to verify a signature.
     */
    public function testToPem(): void
    {
        $signers = [
            'RS256' => new Signer\Rsa\Sha256(),
            'ES256' => new Signer\Ecdsa\Sha256(),
            'ES384' => new Signer\Ecdsa\Sha384(),
            'ES512' => new Signer\Ecdsa\Sha512(),
            'EdDSA' => new Signer\Eddsa(),
        ];

        foreach (self::FIXTURES as $alg => $basename) {
            $jwk = file_get_contents(__DIR__."/fixtures/{$basename}.jwk");
            $this->assertNotFalse($jwk, "read {$basename} jwk fixture");

            $sig = file_get_contents(__DIR__."/fixtures/{$basename}.sig");
            $this->assertNotFalse($sig, "read {$basename} jws fixture");

            $jwk = json_decode($jwk, flags: JSON_THROW_ON_ERROR);
            $pem = JWK::toPem($jwk);

            // NOTE: This check is crucial for testing Ed25519 because of the below hack.
            // Without it, we wouldn't really be testing the DER encoding is correct.
            $result = openssl_get_publickey($pem);
            $this->assertNotFalse($result, "parse {$basename} converted pem");

            [$header, $payload, $signature] = explode('.', $sig);
            $signedPart = "{$header}.{$payload}";

            $header = json_decode(JWK::decodeBase64Url($header), flags: JSON_THROW_ON_ERROR);
            $this->assertEquals($header->alg, $alg, "check {$basename} fixture jws alg");

            $this->assertEquals(JWK::decodeBase64Url($payload), 'hello', 'check fixture payload');

            // HACK: The JWT lib expects a raw EdDSA key, not PEM. This is because it uses the
            // libsodium bindings for EdDSA, rather than the OpenSSL bindings. It appears the
            // PHP OpenSSL bindings can't verify Ed25519 at the moment. This simply extracts
            // the public key from a known offset in the DER encoding.
            if ('EdDSA' === $alg) {
                $lines = explode("\n", trim($pem));
                array_pop($lines);
                array_shift($lines);
                $der = base64_decode(implode('', $lines));
                $key = substr($der, 12);
                $key = Signer\Key\InMemory::plainText($key);
            } else {
                $key = Signer\Key\InMemory::plainText($pem);
            }

            $signature = JWK::decodeBase64Url($signature);
            $result = $signers[$alg]->verify($signature, $signedPart, $key);
            $this->assertTrue($result, "check signature with converted {$basename} key");
        }
    }
}
