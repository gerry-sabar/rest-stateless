<?php

namespace App\Traits;

use DateTimeImmutable;
use Laravel\Passport\Bridge\Scope;
use App\User;
use GuzzleHttp\Psr7\Response;
use Illuminate\Events\Dispatcher;
use Laravel\Passport\Bridge\AccessToken;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;


/**
 * Trait PassportToken
 *
 * @package App\Traits
 */
trait PassportToken
{
	/**
	 * Generate a new unique identifier.
	 *
	 * @param int $length
	 *
	 * @throws OAuthServerException
	 *
	 * @return string
	 */
	private function generateUniqueIdentifier($length = 40)
	{
		try {
			return bin2hex(random_bytes($length));
		} catch (\TypeError $e) {
			throw OAuthServerException::serverError('An unexpected error has occurred');
		} catch (\Error $e) {
			throw OAuthServerException::serverError('An unexpected error has occurred');
		} catch (\Exception $e) {
			// If you get this message, the CSPRNG failed hard.
			throw OAuthServerException::serverError('Could not generate a random string');
		}
	}

	private function issueRefreshToken(AccessTokenEntityInterface $accessToken)
	{
		$maxGenerationAttempts = 10;
		$refreshTokenRepository = app(RefreshTokenRepository::class);

		$refreshToken = $refreshTokenRepository->getNewRefreshToken();
		$refreshToken->setExpiryDateTime((new DateTimeImmutable())->add(Passport::refreshTokensExpireIn()));
		$refreshToken->setAccessToken($accessToken);

		while ($maxGenerationAttempts-- > 0) {
			$refreshToken->setIdentifier($this->generateUniqueIdentifier());
			try {
				$refreshTokenRepository->persistNewRefreshToken($refreshToken);

				return $refreshToken;
			} catch (UniqueTokenIdentifierConstraintViolationException $e) {
				if ($maxGenerationAttempts === 0) {
					throw $e;
				}
			}
		}
	}

	private function createPassportTokenByUser(User $user, $clientId, $tokenScopes = [])
	{
        $scopes = [];
        if (is_array($tokenScopes)) {
            foreach ($tokenScopes as $scope) {
                $scopes[] = new Scope($scope);
            }
        }

		$accessToken = new AccessToken($user->id, $scopes, new Client(null, null, null));
		$accessToken->setIdentifier($this->generateUniqueIdentifier());
		$accessToken->setClient(new Client($clientId, null, null));
		$accessToken->setExpiryDateTime((new DateTimeImmutable())->add(Passport::tokensExpireIn()));

		$accessTokenRepository = new AccessTokenRepository(new TokenRepository(), new Dispatcher());
		$accessTokenRepository->persistNewAccessToken($accessToken);
		$refreshToken = $this->issueRefreshToken($accessToken);

		return [
			'access_token' => $accessToken,
			'refresh_token' => $refreshToken,
		];
	}

	private function sendBearerTokenResponse($accessToken, $refreshToken)
	{
	    //set private key
        $privateKey = new CryptKey('file://'.Passport::keyPath('oauth-private.key'), null, false);
        $accessToken->setPrivateKey($privateKey);

        $response = new BearerTokenResponse();
		$response->setAccessToken($accessToken);
		$response->setRefreshToken($refreshToken);

		$response->setEncryptionKey(app('encrypter')->getKey());

		return $response->generateHttpResponse(new Response);
	}

	/**
	 * @param User $user
	 * @param $clientId
	 * @param bool $output default = false
	 * @return array|\Illuminate\Support\Collection|BearerTokenResponse
	 */
	protected function getBearerTokenByUser(User $user, $clientId=2, $tokenScopes = [], $output = false)
	{
		$passportToken = $this->createPassportTokenByUser($user, $clientId, $tokenScopes);
        $bearerToken = $this->sendBearerTokenResponse($passportToken['access_token'], $passportToken['refresh_token']);

		if (! $output) {
			$bearerToken = json_decode($bearerToken->getBody()->__toString(), true);
		}

		return $bearerToken;
	}
}