<?php

namespace Laravel\Passport\Tests;

use Illuminate\Auth\AuthManager;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Config\Repository;
use Laravel\Passport\UserProviderResolver;
use Mockery as m;
use PHPUnit\Framework\TestCase;

class UserProviderResolverTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function test_a_provider_is_resolved_from_the_username()
    {
        $config = m::mock(Repository::class);
        $config->shouldReceive('get')->with('auth.passport_providers')->andReturn([
            'users',
            'admins'
        ]);
        $manager = m::mock(AuthManager::class);

        $userProviderResolver = new UserProviderResolver($config, $manager);
        $this->assertEquals('users', $userProviderResolver->getProvider('users-1'));
    }

    public function test_a_default_provider_is_resolved_from_the_username_if_none_found()
    {
        $config = m::mock(Repository::class);
        $config->shouldReceive('get')->with('auth.passport_providers')->andReturn([
            'users',
            'admins'
        ]);
        $config->shouldReceive('get')->with('auth.guards.api.provider')->andReturn('users');
        $manager = m::mock(AuthManager::class);

        $userProviderResolver = new UserProviderResolver($config, $manager);
        $this->assertEquals('users', $userProviderResolver->getProvider('1'));
    }

    public function test_username_is_cleaned_from_the_provider()
    {
        $config = m::mock(Repository::class);
        $config->shouldReceive('get')->with('auth.passport_providers')->andReturn([
            'users',
            'admins'
        ]);
        $manager = m::mock(AuthManager::class);

        $userProviderResolver = new UserProviderResolver($config, $manager);
        $this->assertEquals('1', $userProviderResolver->getUsername('users-1'));
    }

    public function test_username_is_not_cleaned_if_provider_is_not_defined()
    {
        $config = m::mock(Repository::class);
        $config->shouldReceive('get')->with('auth.passport_providers')->andReturn([
            'users',
            'admins'
        ]);
        $config->shouldReceive('get')->with('auth.guards.api.provider')->andReturn('users');
        $manager = m::mock(AuthManager::class);

        $userProviderResolver = new UserProviderResolver($config, $manager);
        $this->assertEquals('1', $userProviderResolver->getUsername('1'));
    }

    public function test_user_provider_is_created()
    {
        $config = m::mock(Repository::class);
        $config->shouldReceive('get')->with('auth.passport_providers')->andReturn([
            'users',
            'admins'
        ]);

        $manager = m::mock(AuthManager::class);
        $manager->shouldReceive('createUserProvider')->with('users')->andReturn(m::mock(EloquentUserProvider::class));

        $userProviderResolver = new UserProviderResolver($config, $manager);
        $this->assertInstanceOf(EloquentUserProvider::class, $userProviderResolver->resolve('users-1'));
    }
}
