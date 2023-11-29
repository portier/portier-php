# portier-php

A [Portier] client library for PHP.

[portier]: https://portier.github.io/

### Example

```php
<?php

require 'vendor/autoload.php';

$app = \Slim\Factory\AppFactory::create();
$app->addRoutingMiddleware();
$app->addErrorMiddleware(true, true, true);

$redis = new Redis();
$redis->pconnect('127.0.0.1', 6379);

$portier = new \Portier\Client\Client(
    new \Portier\Client\RedisStore($redis),
    'http://localhost:8000/verify'
);

$app->get('/', function($req, $res) {
    $res = $res
        ->withStatus(200)
        ->withHeader('Content-Type', 'text/html; charset=utf-8');

    $res->getBody()->write(
<<<EOF
        <p>Enter your email address:</p>
        <form method="post" action="/auth">
            <input name="email" type="email">
            <button type="submit">Login</button>
        </form>
EOF
    );

    return $res;
});

$app->post('/auth', function($req, $res) use ($portier) {
    $authUrl = $portier->authenticate($req->getParsedBody()['email']);

    return $res
        ->withStatus(303)
        ->withHeader('Location', $authUrl);
});

$app->post('/verify', function($req, $res) use ($portier) {
    $result = $portier->verify($req->getParsedBody()['id_token']);

    $res = $res
        ->withStatus(200)
        ->withHeader('Content-Type', 'text/html; charset=utf-8');

    $res->getBody()->write(
<<<EOF
        <p>Verified email address {$result->email}!</p>
EOF
    );

    return $res;
});

$app->run();
```
