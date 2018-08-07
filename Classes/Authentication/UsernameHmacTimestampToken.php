<?php
namespace FormatD\HmacAuthentication\Authentication;

/*
 * This file is part of the FormatD.HmacAuthentication package.
 */

use Neos\Flow\Annotations as Flow;

/**
 * Token to authenticate with a hmac
 *
 * @Flow\Scope("singleton")
 */
class UsernameHmacTimestampToken extends \Neos\Flow\Security\Authentication\Token\AbstractToken {

	/**
	 * The password credentials
	 * @var array
	 * @Flow\Transient
	 */
	protected $credentials = ['username' => '', 'hmac' => '', 'timestamp' => ''];

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
		$credentials = $this->hmacService->getCredentialsFromActionRequest($actionRequest);

		if ($credentials) {
			$this->credentials['username'] = $credentials->username;
			$this->credentials['hmac'] = $credentials->hmac;
			$this->credentials['timestamp'] = $credentials->timestamp;
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
		return 'Username: "' . $this->credentials['username'] . '", Hmac: "***", Timestamp: "' . $this->credentials['timestamp'] . '" ';
	}

}
?>