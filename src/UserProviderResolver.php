<?php


namespace Laravel\Passport;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class UserProviderResolver
{
    /**
     * @var Config
     */
    private $config;

    /**
     * @var AuthManager
     */
    private $manager;

    public function __construct(Config $config, AuthManager $manager)
    {
        $this->config = $config;
        $this->manager = $manager;
    }

    public function resolve($username) {
        return $this->manager->createUserProvider($this->getProvider($username));
    }

    /**
     * @param string $username
     * @return string
     */
    public function getProvider($username)
    {
        $passportProvider = collect($this->config->get('auth.passport_providers'))->first(function ($value) use ($username) {
            return Str::startsWith($username, $value . '-');
        });
        return is_null($passportProvider) ? $this->config->get('auth.guards.api.provider') : $passportProvider;
    }

    /**
     * @param string $username
     * @param string $provider
     * @return string
     */
    public function getUsername($username)
    {
        $provider = $this->getProvider($username);
        return Str::startsWith($username, $provider . '-') ? Str::replaceFirst($provider . '-', '', $username) : $username;
    }
}
