<?php

namespace Laravel\Passport;

use Carbon\Carbon;

class TokenRepository
{
    /**
     * Creates a new Access Token.
     *
     * @param  array  $attributes
     * @return \Laravel\Passport\Token
     */
    public function create($attributes)
    {
        return Passport::token()->create($attributes);
    }

    /**
     * Get a token by the given ID.
     *
     * @param  string  $id
     * @return \Laravel\Passport\Token
     */
    public function find($id)
    {
        return Passport::token()->where('id', $id)->first();
    }

    /**
     * Get a token by the given user ID and token ID.
     *
     * @param  string  $id
     * @param  string  $ownerType
     * @param  int  $ownerId
     * @return \Laravel\Passport\Token|null
     */
    public function findForUser($id, $ownerType, $ownerId)
    {
        return Passport::token()->where('id', $id)->where('owner_type', $ownerType)->where('owner_id', $ownerId)->first();
    }

    /**
     * Get the token instances for the given user ID.
     *
     * @param  mixed  $ownerType
     * @param  mixed  $ownerId
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function forOwner($ownerType, $ownerId)
    {
        return Passport::token()->where('owner_type', $ownerType)->where('owner_id', $ownerId)->get();
    }

    /**
     * Get a valid token instance for the given user and client.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $owner
     * @param  \Laravel\Passport\Client  $client
     * @return \Laravel\Passport\Token|null
     */
    public function getValidToken($owner, $client)
    {
        return $client->tokens()
                    ->whereOwner($owner)
                    ->where('revoked', 0)
                    ->where('expires_at', '>', Carbon::now())
                    ->first();
    }

    /**
     * Store the given token instance.
     *
     * @param  \Laravel\Passport\Token  $token
     * @return void
     */
    public function save(Token $token)
    {
        $token->save();
    }

    /**
     * Revoke an access token.
     *
     * @param  string  $id
     * @return mixed
     */
    public function revokeAccessToken($id)
    {
        return Passport::token()->where('id', $id)->update(['revoked' => true]);
    }

    /**
     * Check if the access token has been revoked.
     *
     * @param  string  $id
     *
     * @return bool Return true if this token has been revoked
     */
    public function isAccessTokenRevoked($id)
    {
        if ($token = $this->find($id)) {
            return $token->revoked;
        }

        return true;
    }

    /**
     * Find a valid token for the given user and client.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $owner
     * @param  \Laravel\Passport\Client  $client
     * @return \Laravel\Passport\Token|null
     */
    public function findValidToken($owner, $client)
    {
        return $client->tokens()
                      ->whereOwner($owner)
                      ->where('revoked', 0)
                      ->where('expires_at', '>', Carbon::now())
                      ->latest('expires_at')
                      ->first();
    }
}
