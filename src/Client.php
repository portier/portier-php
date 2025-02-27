<?php

namespace Portier\Client;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer as JwtSigner;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint as JwtConstraint;
use Lcobucci\JWT\Validation\Validator;

/**
 * Client for a Portier broker.
 */
class Client
{
    /**
     * Default Portier broker origin.
     *
     * @var string
     */
    public const DEFAULT_BROKER = 'https://broker.portier.io';

    private const REQUIRED_CLAIMS = ['iss', 'aud', 'exp', 'iat', 'email', 'nonce'];

    private StoreInterface $store;
    private string $redirectUri;
    private string $clientId;

    /**
     * The origin of the Portier broker.
     *
     * @var string
     */
    public $broker = self::DEFAULT_BROKER;

    /**
     * The number of seconds of clock drift to allow.
     *
     * @var int
     */
    public $leeway = 3 * 60;

    /**
     * Constructor.
     *
     * @param StoreInterface $store       store implementation to use
     * @param string         $redirectUri URL that Portier will redirect to
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
        if (false === $localEnd || $localEnd + 1 === strlen($email)) {
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
        if (empty($host) || '[' === $host[0]
               || false !== filter_var($host, FILTER_VALIDATE_IP)) {
            return '';
        }

        return sprintf('%s@%s', $local, $host);
    }

    /**
     * Start authentication of an email address.
     *
     * @param string $email email address to authenticate
     * @param string $state arbitrary state that is returned to the redirect URL via the `state` query parmmeter
     *
     * @return string URL to redirect the browser to
     */
    public function authenticate(string $email, ?string $state = null): string
    {
        $authEndpoint = $this->fetchDiscovery()->authorization_endpoint ?? null;
        if (!is_string($authEndpoint)) {
            throw new \Exception('No authorization_endpoint in discovery document');
        }

        $nonce = $this->store->createNonce($email);
        $query = [
            'login_hint' => $email,
            'scope' => 'openid email',
            'nonce' => $nonce,
            'response_type' => 'id_token',
            'response_mode' => 'form_post',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
        ];
        if (null !== $state) {
            $query['state'] = $state;
        }

        return $authEndpoint.'?'.http_build_query($query);
    }

    /**
     * Verify a token received on our `redirect_uri`.
     *
     * @param string $token the received `id_token` parameter value
     *
     * @return string the verified email address
     */
    public function verify(string $token): string
    {
        assert(!empty($token));
        assert(!empty($this->broker));
        assert(!empty($this->clientId));

        // Parse the token.
        $parser = new Parser(new JoseEncoder());
        $token = $parser->parse($token);
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
        $publicKey = '';
        foreach ($keysDoc->keys as $key) {
            if ($key instanceof \stdClass
                && isset($key->alg) && 'RS256' === $key->alg
                && isset($key->kid) && $key->kid === $kid
            ) {
                try {
                    $publicKey = JWK::toPem($key);
                } catch (\Exception) {
                }
                break;
            }
        }
        if ('' === $publicKey) {
            throw new \Exception('Cannot find the public key used to sign the token');
        }
        $publicKey = JwtSigner\Key\InMemory::plainText($publicKey);

        // Validate the token claims.
        $clock = \Lcobucci\Clock\SystemClock::fromUTC();
        $leeway = new \DateInterval('PT'.$this->leeway.'S');
        $validator = new Validator();
        $validator->assert($token, new JwtConstraint\SignedWith(new JwtSigner\Rsa\Sha256(), $publicKey));
        $validator->assert($token, new JwtConstraint\IssuedBy($this->broker));
        $validator->assert($token, new JwtConstraint\PermittedFor($this->clientId));
        $validator->assert($token, new JwtConstraint\LooseValidAt($clock, $leeway));

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

        $state = $claims->get('state');
        if (!is_string($state)) {
            $state = null;
        }

        // Return the normalized email.
        return $email;
    }

    /**
     * Fetches the OpenID discovery document from the broker.
     */
    private function fetchDiscovery(): \stdClass
    {
        $discoveryUrl = $this->broker.'/.well-known/openid-configuration';

        return $this->store->fetchCached('discovery', $discoveryUrl);
    }

    /**
     * Get the origin for a URL.
     */
    private static function getOrigin(string $url): string
    {
        $components = parse_url($url);
        if (false === $components) {
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

        $res = $scheme.'://'.$host;
        if (isset($components['port'])) {
            $port = $components['port'];
            if (('http' === $scheme && 80 !== $port)
                    || ('https' === $scheme && 443 !== $port)) {
                $res .= ':'.$port;
            }
        }

        return $res;
    }
}
