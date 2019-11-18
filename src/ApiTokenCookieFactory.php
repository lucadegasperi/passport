<?php

namespace Laravel\Passport;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Encryption\Encrypter;
use Symfony\Component\HttpFoundation\Cookie;

class ApiTokenCookieFactory
{
    /**
     * The configuration repository implementation.
     *
     * @var \Illuminate\Contracts\Config\Repository
     */
    protected $config;

    /**
     * The encrypter implementation.
     *
     * @var \Illuminate\Contracts\Encryption\Encrypter
     */
    protected $encrypter;

    /**
     * Create an API token cookie factory instance.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Encryption\Encrypter  $encrypter
     * @return void
     */
    public function __construct(Config $config, Encrypter $encrypter)
    {
        $this->config = $config;
        $this->encrypter = $encrypter;
    }

    /**
     * Create a new API token cookie.
     *
     * @param  mixed  $ownerType
     * @param  mixed  $ownerId
     * @param  string  $csrfToken
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    public function make($ownerType, $ownerId, $csrfToken)
    {
        $config = $this->config->get('session');

        $expiration = Carbon::now()->addMinutes($config['lifetime']);

        return new Cookie(
            Passport::cookie(),
            $this->createToken($ownerType, $ownerId, $csrfToken, $expiration),
            $expiration,
            $config['path'],
            $config['domain'],
            $config['secure'],
            true,
            false,
            $config['same_site'] ?? null
        );
    }

    /**
     * Create a new JWT token for the given user ID and CSRF token.
     *
     * @param  mixed  $ownerType
     * @param  mixed  $ownerId
     * @param  string  $csrfToken
     * @param  \Carbon\Carbon  $expiration
     * @return string
     */
    protected function createToken($ownerType, $ownerId, $csrfToken, Carbon $expiration)
    {
        return JWT::encode([
            'sub' => $ownerType . '-' . $ownerId,
            'csrf' => $csrfToken,
            'expiry' => $expiration->getTimestamp(),
        ], $this->encrypter->getKey());
    }
}
