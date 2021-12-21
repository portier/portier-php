<?php

namespace Portier\Client;

use Lcobucci\JWT\Configuration as JwtConfig;
use Lcobucci\JWT\Validation\Constraint as JwtConstraint;
use Lcobucci\JWT\Signer as JwtSigner;

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

    private StoreInterface $store;
    private string $redirectUri;
    private string $clientId;

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
     * Normalize an email address.
     *
     * This method is useful when comparing user input to an email address
     * returned in a Portier token. It is not necessary to call this before
     * `authenticate`, normalization is already part of the authentication
     * process.
     */
    public static function normalize(string $email): string
    {
        // Repeat these checks here, so PHPStan understands.
        assert(defined('MB_CASE_FOLD') && function_exists('idn_to_ascii'));

        $localEnd = strrpos($email, '@');
        if ($localEnd === false) {
            return '';
        }

        $local = mb_convert_case(
            substr($email, 0, $localEnd),
            MB_CASE_FOLD
        );
        if (empty($local)) {
            return '';
        }

        $host = idn_to_ascii(
            substr($email, $localEnd + 1),
            IDNA_USE_STD3_RULES | IDNA_CHECK_BIDI,
            INTL_IDNA_VARIANT_UTS46
        );
        if (empty($host) || $host[0] === '[' ||
               filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return '';
        }

        return sprintf('%s@%s', $local, $host);
    }

    /**
     * Start authentication of an email address.
     * @param  string $email  Email address to authenticate.
     * @return string         URL to redirect the browser to.
     */
    public function authenticate(string $email): string
    {
        $authEndpoint = $this->fetchDiscovery()->authorization_endpoint ?? null;
        if (!is_string($authEndpoint)) {
            throw new \Exception('No authorization_endpoint in discovery document');
        }

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
        return $authEndpoint . '?' . $query;
    }

    /**
     * Verify a token received on our `redirect_uri`.
     * @param  string $token  The received `id_token` parameter value.
     * @return string         The verified email address.
     */
    public function verify(string $token): string
    {
        // Parse the token.
        $jwt = JwtConfig::forUnsecuredSigner();
        $token = $jwt->parser()->parse($token);
        assert($token instanceof \Lcobucci\JWT\UnencryptedToken);

        // Get the key ID from the token header.
        $kid = $token->headers()->get('kid');
        if (empty($kid)) {
            throw new \Exception('Token has no "kid" header field');
        }

        // Fetch broker keys.
        $jwksUri = $this->fetchDiscovery()->jwks_uri ?? null;
        if (!is_string($jwksUri)) {
            throw new \Exception('No jwks_uri in discovery document');
        }

        $keysDoc = $this->store->fetchCached('keys', $jwksUri);
        if (!isset($keysDoc->keys) || !is_array($keysDoc->keys)) {
            throw new \Exception('Keys document incorrectly formatted');
        }

        // Find the matching public key, and verify the signature.
        $publicKey = null;
        foreach ($keysDoc->keys as $key) {
            if ($key instanceof \stdClass &&
                    isset($key->alg) && $key->alg === 'RS256' &&
                    isset($key->kid) && $key->kid === $kid &&
                    isset($key->n) && isset($key->e)) {
                $publicKey = self::parseJwk($key);
                break;
            }
        }
        if ($publicKey === null) {
            throw new \Exception('Cannot find the public key used to sign the token');
        }

        // Validate the token claims.
        $clock = \Lcobucci\Clock\SystemClock::fromUTC();
        $leeway = new \DateInterval('PT' . $this->leeway . 'S');
        $constraints = [
            new JwtConstraint\SignedWith(new JwtSigner\Rsa\Sha256(), $publicKey),
            new JwtConstraint\IssuedBy($this->broker),
            new JwtConstraint\PermittedFor($this->clientId),
            new JwtConstraint\LooseValidAt($clock, $leeway),
        ];
        $jwt->validator()->assert($token, ...$constraints);

        // Check that the required token claims are set.
        $claims = $token->claims();
        $missing = array_filter(self::REQUIRED_CLAIMS, function (string $name) use ($claims) {
            return !$claims->has($name);
        });
        if (!empty($missing)) {
            throw new \Exception(sprintf('Token is missing claims: %s', implode(', ', $missing)));
        }

        $nonce = $claims->get('nonce');
        $email = $claims->get('email');
        $emailOriginal = $claims->get('email_original', $email);
        if (!is_string($nonce)) {
            throw new \Exception(sprintf('Token claim "nonce" is not a string'));
        }
        if (!is_string($email)) {
            throw new \Exception(sprintf('Token claim "email" is not a string'));
        }
        if (!is_string($emailOriginal)) {
            throw new \Exception(sprintf('Token claim "email_original" is not a string'));
        }

        // Consume the nonce.
        $this->store->consumeNonce($nonce, $emailOriginal);

        // Return the normalized email.
        return $email;
    }

    /**
     * Fetches the OpenID discovery document from the broker.
     */
    private function fetchDiscovery(): \stdClass
    {
        $discoveryUrl = $this->broker . '/.well-known/openid-configuration';
        return $this->store->fetchCached('discovery', $discoveryUrl);
    }

    /**
     * Parse a JWK into a PEM public key.
     */
    private static function parseJwk(\stdClass $jwk): JwtSigner\Key
    {
        $n = gmp_init(bin2hex(self::decodeBase64Url($jwk->n)), 16);
        $e = gmp_init(bin2hex(self::decodeBase64Url($jwk->e)), 16);

        $seq = new \FG\ASN1\Universal\Sequence();
        $seq->addChild(new \FG\ASN1\Universal\Integer(gmp_strval($n)));
        $seq->addChild(new \FG\ASN1\Universal\Integer(gmp_strval($e)));
        $pkey = new \FG\X509\PublicKey(bin2hex($seq->getBinary()));

        $encoded = base64_encode($pkey->getBinary());

        return JwtSigner\Key\InMemory::plainText(
            "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split($encoded, 64, "\n") .
            "-----END PUBLIC KEY-----\n"
        );
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

    private static function decodeBase64Url(string $input): string
    {
        $output = base64_decode(strtr($input, '-_', '+/'), true);
        if ($output === false) {
            throw new \Exception("Invalid base64");
        }

        return $output;
    }
}
