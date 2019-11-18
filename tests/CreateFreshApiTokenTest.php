<?php

namespace Laravel\Passport\Tests;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Laravel\Passport\ApiTokenCookieFactory;
use Laravel\Passport\Http\Middleware\CreateFreshApiToken;
use Laravel\Passport\Passport;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;

class CreateFreshApiTokenTest extends TestCase
{
    protected function tearDown(): void
    {
        m::close();
    }

    public function testShouldReceiveAFreshToken()
    {
        $cookieFactory = m::mock(ApiTokenCookieFactory::class);

        $middleware = new CreateFreshApiToken($cookieFactory);
        $request = m::mock(Request::class)->makePartial();

        $response = new Response;

        $guard = 'guard';
        $user = m::mock();

        $user->shouldReceive('getMorphClass')->andReturn($userMorphClass = 'users');
        $user->shouldReceive('getKey')->andReturn($userKey = 1);

        $request->shouldReceive('session')->andReturn($session = m::mock());
        $request->shouldReceive('isMethod')->with('GET')->once()->andReturn(true);
        $request->shouldReceive('user')->with($guard)->times(3)->andReturn($user);
        $session->shouldReceive('token')->withNoArgs()->once()->andReturn($token = 't0k3n');

        $cookieFactory->shouldReceive('make')
            ->with($userMorphClass, $userKey, $token)
            ->once()
            ->andReturn(new Cookie(Passport::cookie()));

        $result = $middleware->handle($request, function () use ($response) {
            return $response;
        }, $guard);

        $this->assertSame($response, $result);
        $this->assertTrue($this->hasPassportCookie($response));
    }

    public function testShouldNotReceiveAFreshTokenForOtherHttpVerbs()
    {
        $cookieFactory = m::mock(ApiTokenCookieFactory::class);

        $middleware = new CreateFreshApiToken($cookieFactory);
        $request = Request::create('/', 'POST');
        $response = new Response;

        $result = $middleware->handle($request, function () use ($response) {
            return $response;
        });

        $this->assertSame($response, $result);
        $this->assertFalse($this->hasPassportCookie($response));
    }

    public function testShouldNotReceiveAFreshTokenForAnInvalidUser()
    {
        $cookieFactory = m::mock(ApiTokenCookieFactory::class);

        $middleware = new CreateFreshApiToken($cookieFactory);
        $request = Request::create('/', 'GET');
        $response = new Response;

        $request->setUserResolver(function () {
        });

        $result = $middleware->handle($request, function () use ($response) {
            return $response;
        });

        $this->assertSame($response, $result);
        $this->assertFalse($this->hasPassportCookie($response));
    }

    public function testShouldNotReceiveAFreshTokenForResponseThatAlreadyHasToken()
    {
        $cookieFactory = m::mock(ApiTokenCookieFactory::class);

        $middleware = new CreateFreshApiToken($cookieFactory);
        $request = Request::create('/', 'GET');

        $response = (new Response)->withCookie(
            new Cookie(Passport::cookie())
        );

        $request->setUserResolver(function () {
            $user = m::mock();

            $user->shouldReceive('getMorphClass')->andReturn('users');
            $user->shouldReceive('getKey')->andReturn(1);

            return $user;
        });

        $result = $middleware->handle($request, function () use ($response) {
            return $response;
        });

        $this->assertSame($response, $result);
        $this->assertTrue($this->hasPassportCookie($response));
    }

    protected function hasPassportCookie($response)
    {
        foreach ($response->headers->getCookies() as $cookie) {
            if ($cookie->getName() === Passport::cookie()) {
                return true;
            }
        }

        return false;
    }
}
