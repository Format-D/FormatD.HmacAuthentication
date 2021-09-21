<?php
namespace FormatD\HmacAuthentication\Service;

/*
 * This file is part of the FormatD.HmacAuthentication package.
 */

use FormatD\HmacAuthentication\Domain\Model\HmacToken;
use Neos\Flow\Annotations as Flow;

/**
 *
 * @Flow\Scope("singleton")
 */
class HmacService {

    const HTK_Username = 'username';
    const HTK_Provider = 'authenticationProviderAlias';

    /**
	 * @Flow\Inject
	 * @var \Neos\Flow\Security\Cryptography\HashService
	 */
	protected $hashService;

	/**
	 * @Flow\Inject
	 * @var \Neos\Flow\Utility\Now
	 */
	protected $now;

	/**
	 * @Flow\InjectConfiguration(package="FormatD.HmacAuthentication.hmacTimeoutInterval")
	 * @var string
	 */
	protected $hmacTimeoutInterval;

    /**
     * @Flow\InjectConfiguration(package="FormatD.HmacAuthentication.allowedAuthenticationProviders")
     * @var array
     */
    protected $allowedAuthenticationProviders;

    /**
	 * @param string $accountIdentifier
     * @param string $authenticationProviderName
	 */
	public function generateHmacAuthenticationQueryStringPart($accountIdentifier, string $authenticationProviderName = null)
	{
		return '__authentication[HmacAuthentication][authToken]=' . $this->encodeAuthToken($accountIdentifier, $authenticationProviderName);
	}

	/**
	 * @param \Neos\Flow\Mvc\ActionRequest $actionRequest
	 * @return HmacToken
	 */
	public function getCredentialsFromActionRequest(\Neos\Flow\Mvc\ActionRequest $actionRequest)
	{
		$arguments = $actionRequest->getInternalArguments();

		$varsEncoded = \Neos\Utility\ObjectAccess::getPropertyPath($arguments, '__authentication.HmacAuthentication.authToken');

		if (!$varsEncoded) {
			return NULL;
		}

		return $this->decodeAuthToken($varsEncoded);
	}

    /**
     * @param string $name
     * @return string|null
     */
	public function getAuthenticationProviderAliasFromName(string $name) {
        foreach ($this->allowedAuthenticationProviders as $alias => $provider) {
            if($name === $provider) {
                return $alias;
            }
        }
        return null;
    }

    /**
     * @param string $accountIdentifier
     * @param string|null $authenticationProviderName
     * @return string
     * @throws \FormatD\HmacAuthentication\Exception
     */
	public function encodeAuthToken($accountIdentifier, string $authenticationProviderName = null)
	{
		if (strlen($accountIdentifier) < 1) {
			throw new \FormatD\HmacAuthentication\Exception('Accountidentifier empty', 1513764288);
		}

		$token = new HmacToken();

		$token->setTimestamp($this->now->getTimestamp());
        $token->setPayloadEntry(self::HTK_Username, $accountIdentifier);

        if ($authenticationProviderName) {
            $authenticationProviderAlias = $this->getAuthenticationProviderAliasFromName($authenticationProviderName);
            if($authenticationProviderAlias !== null) {
                $token->setPayloadEntry(self::HTK_Provider, $authenticationProviderAlias);
            }
        }

		$hmac = $this->generateHmac($token->getHashData(), $this->now->getTimestamp());
        $token->setHmac($hmac);

		return urlencode(base64_encode($token->toJson()));
	}

	/**
	 * @param string $authToken
	 * @return HmacToken
	 */
	public function decodeAuthToken($authToken)
	{
		return HmacToken::FromJson(base64_decode(urldecode($authToken)));
    }

	/**
	 * @param string $authToken
	 * @return object
	 */
	public function decodeAndValidateAuthToken($authToken)
	{
		$token = $this->decodeAuthToken($authToken);

		if (!$this->validateToken($authToken)) {
			throw new \FormatD\HmacAuthentication\Exception('Invalid Auth Token', 1532459848);
		}

		return $token;
	}

	/**
	 * @param string $string
	 * @param int $timestamp
	 */
	public function generateHmac($string, $timestamp)
	{
		return $this->hashService->generateHmac($string . '|' . $timestamp);
	}

    /**
     * @param HmacToken $token
     * @return bool
     */
	public function validateToken($token) {
        return $this->validateHmac($token->getHashData(), $token->getTimestamp(), $token->getHmac());
    }

	/**
	 * @param string $string
	 * @param int $timestamp
	 * @param string $providedHmac
	 */
	public function validateHmac($string, $timestamp, $providedHmac)
	{

		// check if hmac is timed out
		if ($timestamp < ($this->now->getTimestamp() - $this->hmacTimeoutInterval)) {
			return FALSE;
		}

		if (!$this->hashService->validateHmac($string . '|' . $timestamp, $providedHmac)) {
			return FALSE;
		}

		return TRUE;
	}

}
?>