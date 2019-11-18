<?php

namespace Laravel\Passport\Bridge;

use DateTime;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Events\AccessTokenCreated;
use Laravel\Passport\TokenRepository;
use Laravel\Passport\UserProviderResolver;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    use FormatsScopesForStorage;

    /**
     * The token repository instance.
     *
     * @var \Laravel\Passport\TokenRepository
     */
    protected $tokenRepository;

    /**
     * The event dispatcher instance.
     *
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;

    /**
     * @var UserProviderResolver
     */
    protected $resolver;

    /**
     * Create a new repository instance.
     *
     * @param  \Laravel\Passport\TokenRepository  $tokenRepository
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     */
    public function __construct(TokenRepository $tokenRepository, Dispatcher $events, UserProviderResolver $resolver)
    {
        $this->events = $events;
        $this->tokenRepository = $tokenRepository;
        $this->resolver = $resolver;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        return new AccessToken($userIdentifier, $scopes, $clientEntity);
    }

    /**
     * {@inheritdoc}
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $this->tokenRepository->create([
            'id' => $accessTokenEntity->getIdentifier(),
            'owner_type' => $this->resolver->getProvider($accessTokenEntity->getUserIdentifier()),
            'owner_id' => $this->resolver->getUsername($accessTokenEntity->getUserIdentifier()),
            'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
            'scopes' => $this->scopesToArray($accessTokenEntity->getScopes()),
            'revoked' => false,
            'created_at' => new DateTime,
            'updated_at' => new DateTime,
            'expires_at' => $accessTokenEntity->getExpiryDateTime(),
        ]);

        $this->events->dispatch(new AccessTokenCreated(
            $accessTokenEntity->getIdentifier(),
            $accessTokenEntity->getUserIdentifier(),
            $accessTokenEntity->getClient()->getIdentifier()
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken($tokenId)
    {
        $this->tokenRepository->revokeAccessToken($tokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function isAccessTokenRevoked($tokenId)
    {
        return $this->tokenRepository->isAccessTokenRevoked($tokenId);
    }
}
