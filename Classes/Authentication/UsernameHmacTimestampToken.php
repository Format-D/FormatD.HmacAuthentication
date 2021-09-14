<?php
namespace FormatD\HmacAuthentication\Authentication;

/*
 * This file is part of the FormatD.HmacAuthentication package.
 */

use Neos\Flow\Annotations as Flow;

/**
 * Token to authenticate with a hmac
 */
class UsernameHmacTimestampToken extends \Neos\Flow\Security\Authentication\Token\AbstractToken {

    const CRED_TOKEN = 'token';

	/**
	 * The password credentials
	 * @var array
	 * @Flow\Transient
	 */
	protected $credentials = [self::CRED_TOKEN => ''];

	/**
	 * @var \Neos\Flow\Utility\Environment
	 * @Flow\Inject
	 */
	protected $environment;

	/**
	 * @Flow\Inject
	 * @var \FormatD\HmacAuthentication\Service\HmacService
	 */
	protected $hmacService;

	/**
	 * Updates the credentials from the GET vars, if the get parameters
	 * are available. Sets the authentication status to AUTHENTICATION_NEEDED, if credentials have been sent.
	 *
	 * Note: You need to send the credentials in this GET parameter:
	 *       __authentication[FormatD][HmacAuthentication][authToken]
	 *
	 * @param ActionRequest $actionRequest The current action request
	 * @return void
	 */
	public function updateCredentials(\Neos\Flow\Mvc\ActionRequest $actionRequest)
	{
		$token = $this->hmacService->getCredentialsFromActionRequest($actionRequest);

		if ($token) {
		    $this->credentials[self::CRED_TOKEN] = $token->toJson();
			$this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
		}
	}

	/**
	 * Returns a string representation of the token for logging purposes.
	 *
	 * @return string
	 */
	public function __toString()
	{
	    $token = $this->credentials[self::CRED_TOKEN];
		return 'Token: "' . $token . '"';
	}

}
?>