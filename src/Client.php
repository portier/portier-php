<?php

namespace Portier\Client;

/**
 * Client for a Portier broker.
 */
class Client
{
    /**
     * Default Portier broker origin.
     * @var string
     */
    public const DEFAULT_BROKER = 'https://broker.portier.io';

    private const REQUIRED_CLAIMS = ['iss', 'aud', 'exp', 'iat', 'email', 'nonce'];

    private $store;
    private $redirectUri;
    private $clientId;

    /**
     * The origin of the Portier broker.
     * @var string
     */
    public $broker = self::DEFAULT_BROKER;

    /**
     * The number of seconds of clock drift to allow.
     * @var int
     */
    public $leeway = 3 * 60;

    /**
     * Constructor
     * @param StoreInterface  $store        Store implementation to use.
     * @param string          $redirectUri  URL that Portier will redirect to.
     */
    public function __construct(StoreInterface $store, string $redirectUri)
    {
        $this->store = $store;
        $this->redirectUri = $redirectUri;

        $this->clientId = self::getOrigin($this->redirectUri);
    }

    /**
     * Normalize one or more email addresses.
     *
     * This method is useful when comparing user input to an email address
     * returned in a Portier token. It is not necessary to call this before
     * `authenticate`, normalization is already part of the authentication
     * process.
     *
     * This is currently implemented by making an HTTP call to Portier, without
     * cache.
     *
     * @param  string[] $emails Email addresses to normalize.
     * @return string[]         Normalized email addresses, empty strings for invalid.
     */
    public function normalize(array $emails): array
    {
        $res = $this->store->guzzle->post(
            $this->broker . '/normalize',
            ['body' => implode("\n", $emails)]
        );
        return explode("\n", (string) $res->getBody());
    }

    /**
     * Start authentication of an email address.
     * @param  string $email  Email address to authenticate.
     * @return string         URL to redirect the browser to.
     */
    public function authenticate(string $email): string
    {
        $nonce = $this->store->createNonce($email);
        $query = http_build_query([
            'login_hint' => $email,
            'scope' => 'openid email',
            'nonce' => $nonce,
            'response_type' => 'id_token',
            'response_mode' => 'form_post',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
        ]);
        return $this->broker . '/auth?' . $query;
    }

    /**
     * Verify a token received on our `redirect_uri`.
     * @param  string $token  The received `id_token` parameter value.
     * @return string         The verified email address.
     */
    public function verify(string $token): string
    {
        // Parse token and get the key ID from its header.
        $parser = new \Lcobucci\JWT\Parser();
        $token = $parser->parse($token);
        $kid = $token->getHeader('kid');

        // Fetch broker keys.
        $discoveryUrl = $this->broker . '/.well-known/openid-configuration';
        $discoveryDoc = $this->store->fetchCached('discovery', $discoveryUrl);
        if (!isset($discoveryDoc->jwks_uri) || !is_string($discoveryDoc->jwks_uri)) {
            throw new \Exception('Discovery document incorrectly formatted');
        }

        $keysDoc = $this->store->fetchCached('keys', $discoveryDoc->jwks_uri);
        if (!isset($keysDoc->keys) || !is_array($keysDoc->keys)) {
            throw new \Exception('Keys document incorrectly formatted');
        }

        // Find the matching public key, and verify the signature.
        $publicKey = null;
        foreach ($keysDoc->keys as $key) {
            if (isset($key->alg) && $key->alg === 'RS256' &&
                    isset($key->kid) && $key->kid === $kid &&
                    isset($key->n) && isset($key->e)) {
                $publicKey = $key;
                break;
            }
        }
        if ($publicKey === null) {
            throw new \Exception('Cannot find the public key used to sign the token');
        }
        if (!$token->verify(
            new \Lcobucci\JWT\Signer\Rsa\Sha256(),
            self::parseJwk($publicKey)
        )) {
            throw new \Exception('Token signature did not validate');
        }

        // Check that the required token claims are set.
        $missing = array_filter(self::REQUIRED_CLAIMS, function (string $name) use ($token) {
            return !$token->hasClaim($name);
        });
        if (!empty($missing)) {
            throw new \Exception(sprintf('Token is missing claims: %s', implode(', ', $missing)));
        }

        // Validate the token claims.
        $vdata = new \Lcobucci\JWT\ValidationData();
        $vdata->setIssuer($this->broker);
        $vdata->setAudience($this->clientId);
        if (!$token->validate($vdata)) {
            throw new \Exception('Token claims did not validate');
        }

        // Consume the nonce.
        $nonce = $token->getClaim('nonce');
        $email = $token->getClaim('email');
        $emailOriginal = $token->getClaim('email_original', $email);
        $this->store->consumeNonce($nonce, $emailOriginal);

        // Return the normalized email.
        return $email;
    }

    /**
     * Parse a JWK into a PEM public key.
     */
    private static function parseJwk($jwk): string
    {
        $n = gmp_init(bin2hex(\Base64Url\Base64Url::decode($jwk->n)), 16);
        $e = gmp_init(bin2hex(\Base64Url\Base64Url::decode($jwk->e)), 16);

        $seq = new \FG\ASN1\Universal\Sequence();
        $seq->addChild(new \FG\ASN1\Universal\Integer(gmp_strval($n)));
        $seq->addChild(new \FG\ASN1\Universal\Integer(gmp_strval($e)));
        $pkey = new \FG\X509\PublicKey(bin2hex($seq->getBinary()));

        $encoded = base64_encode($pkey->getBinary());

        return
            "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split($encoded, 64, "\n") .
            "-----END PUBLIC KEY-----\n";
    }

    /**
     * Get the origin for a URL
     */
    private static function getOrigin(string $url): string
    {
        $components = parse_url($url);
        if ($components === false) {
            throw new \Exception('Could not parse the redirect URI');
        }

        if (!isset($components['scheme'])) {
            throw new \Exception('No scheme set in redirect URI');
        }
        $scheme = $components['scheme'];

        if (!isset($components['host'])) {
            throw new \Exception('No host set in redirect URI');
        }
        $host = $components['host'];

        $res = $scheme . '://' . $host;
        if (isset($components['port'])) {
            $port = $components['port'];
            if (($scheme === 'http' && $port !== 80) ||
                    ($scheme === 'https' && $port !== 443)) {
                $res .= ':' . $port;
            }
        }

        return $res;
    }
}
