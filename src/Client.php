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
    private string $clientOrigin;

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

        $this->clientOrigin = self::getOrigin($this->redirectUri);
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
        $discovery = $this->fetchDiscovery();

        $authEndpoint = $discovery->config->authorization_endpoint ?? null;
        if (!is_string($authEndpoint)) {
            throw new \Exception('No authorization_endpoint in discovery document');
        }

        // Prefer Ed25519. Note that `alg=EdDSA` could also mean Ed448,
        // so we must also inspect the key set.
        $clientId = $this->clientOrigin;
        $supportedAlgs = $discovery->config->id_token_signing_alg_values_supported ?? null;
        if (is_array($supportedAlgs) && in_array('EdDSA', $supportedAlgs)) {
            $foundEd25519 = false;
            $foundOtherEdDSA = false;
            foreach ($discovery->jwks as $jwk) {
                if (($jwk->use ?? null) === 'sig' && ($jwk->alg ?? null) === 'EdDSA') {
                    if (($jwk->crv ?? null) === 'Ed25519') {
                        $foundEd25519 = true;
                    } else {
                        $foundOtherEdDSA = true;
                        break;
                    }
                }
            }
            if ($foundEd25519 && !$foundOtherEdDSA) {
                $clientId .= '?id_token_signed_response_alg=EdDSA';
            }
        }

        $nonce = $this->store->createNonce($clientId, $email);
        $query = [
            'login_hint' => $email,
            'scope' => 'openid email',
            'nonce' => $nonce,
            'response_type' => 'id_token',
            'response_mode' => 'form_post',
            'client_id' => $clientId,
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

        // Parse the token.
        $parser = new Parser(new JoseEncoder());
        $token = $parser->parse($token);
        assert($token instanceof \Lcobucci\JWT\UnencryptedToken);

        // Get the key ID from the token header.
        $kid = $token->headers()->get('kid');
        if (empty($kid)) {
            throw new \Exception('Token has no "kid" header field');
        }

        // Find the matching public key, and verify the signature.
        $matchingJwk = null;
        foreach ($this->fetchDiscovery()->jwks as $jwk) {
            if (($jwk->use ?? null) === 'sig' && ($jwk->kid ?? null) === $kid) {
                $matchingJwk = $jwk;
                break;
            }
        }
        if (null === $matchingJwk) {
            throw new \Exception('Cannot find the JWK used to sign the token');
        }

        $alg = $matchingJwk->alg ?? null;
        if (!is_string($alg)) {
            throw new \Exception('Missing "alg" on JWK');
        }
        switch ($alg) {
            case 'RS256':
                $key = JWK::toPem($matchingJwk);
                $signer = new JwtSigner\Rsa\Sha256();
                break;

            case 'EdDSA':
                $crv = $matchingJwk->crv ?? null;
                $x = $matchingJwk->x ?? null;
                if (!is_string($crv) || !is_string($x)) {
                    throw new \Exception('Incomplete EdDSA JWK');
                }
                if ('Ed25519' !== $crv) {
                    throw new \Exception('Unsupported EdDSA crv: '.substr($crv, 0, 10));
                }

                $key = JWK::decodeBase64Url($x);
                $signer = new JwtSigner\Eddsa();
                break;

            default:
                throw new \Exception('Unsupported kty: '.substr($alg, 0, 10));
        }
        if (empty($key)) {
            throw new \Exception('Invalid JWK');
        }
        $key = JwtSigner\Key\InMemory::plainText($key);

        // Validate the token claims.
        $clock = \Lcobucci\Clock\SystemClock::fromUTC();
        $leeway = new \DateInterval('PT'.$this->leeway.'S');
        $validator = new Validator();
        $validator->assert($token, new JwtConstraint\SignedWith($signer, $key));
        $validator->assert($token, new JwtConstraint\IssuedBy($this->broker));
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
        $aud = $claims->get('aud');
        $email = $claims->get('email');
        $emailOriginal = $claims->get('email_original', $email);
        if (!is_string($nonce)) {
            throw new \Exception(sprintf('Token claim "nonce" is not a string'));
        }
        if (!is_array($aud) || 1 !== count($aud) || !is_string($aud[0])) {
            throw new \Exception(sprintf('Token claim "aud" is not a string'));
        }
        if (!is_string($email)) {
            throw new \Exception(sprintf('Token claim "email" is not a string'));
        }
        if (!is_string($emailOriginal)) {
            throw new \Exception(sprintf('Token claim "email_original" is not a string'));
        }

        // Consume the nonce.
        $clientId = $aud[0];
        $this->store->consumeNonce($nonce, $clientId, $emailOriginal);

        // Verify the correct signing algorithm was used.
        $expectedAlg = 'RS256';
        $sepIdx = strpos($clientId, '?');
        if (false !== $sepIdx) {
            $params = [];
            parse_str(substr($clientId, $sepIdx + 1), $params);
            $expectedAlg = $params['id_token_signed_response_alg'] ?? 'RS256';
        }
        if ($alg !== $expectedAlg) {
            throw new \Exception(sprintf('Token signed using incorrect algorithm'));
        }

        // Return the normalized email.
        return $email;
    }

    /**
     * Fetches the OpenID configuration and keys from the broker.
     *
     * @return object{config: \stdClass, jwks: \stdClass[]}
     */
    private function fetchDiscovery(): object
    {
        $configUrl = $this->broker.'/.well-known/openid-configuration';
        $config = $this->store->fetchCached('config', $configUrl);

        $jwksUri = $config->jwks_uri ?? null;
        if (!is_string($jwksUri)) {
            throw new \Exception('No jwks_uri in openid-configuration');
        }

        $jwksDoc = $this->store->fetchCached('keys', $jwksUri);
        $jwks = $jwksDoc->keys ?? null;
        if (!is_array($jwks)) {
            throw new \Exception('JWKs document incorrectly formatted');
        }
        foreach ($jwks as $jwk) {
            if (!($jwk instanceof \stdClass)) {
                throw new \Exception('JWKs document incorrectly formatted');
            }
        }
        /** @var \stdClass[] */
        $jwks = $jwks;

        return (object) [
            'config' => $config,
            'jwks' => $jwks,
        ];
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
