<?php
namespace FormatD\HmacAuthentication\Service;

/*
 * This file is part of the FormatD.HmacAuthentication package.
 */

use Neos\Flow\Annotations as Flow;

/**
 *
 * @Flow\Scope("singleton")
 */
class HmacService {

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
	 * @param string $accountIdentifier
	 */
	public function generateHmacAuthenticationQueryStringPart($accountIdentifier)
	{
		return '__authentication[HmacAuthentication][authToken]=' . $this->encodeAuthToken($accountIdentifier);
	}

	/**
	 * @param \Neos\Flow\Mvc\ActionRequest $actionRequest
	 * @return array
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
	 * @param string $accountIdentifier
	 * @return string
	 */
	public function encodeAuthToken($accountIdentifier)
	{

		if (strlen($accountIdentifier) < 1) {
			throw new \FormatD\HmacAuthentication\Exception('Accountidentifier empty', 1513764288);
		}

		$vars = array (
			'username' => $accountIdentifier,
			'hmac' => $this->generateHmac($accountIdentifier, $this->now->getTimestamp()),
			'timestamp' => $this->now->getTimestamp()
		);

		return urlencode(base64_encode(json_encode($vars)));
	}

	/**
	 * @param string $authToken
	 * @return object
	 */
	public function decodeAuthToken($authToken)
	{
		$varsDecoded = json_decode(base64_decode(urldecode($authToken)));

		if (!is_object($varsDecoded)) {
			return NULL;
		}

		return $varsDecoded;
	}

	/**
	 * @param string $authToken
	 * @return object
	 */
	public function decodeAndValidateAuthToken($authToken)
	{
		$varsDecoded = $this->decodeAuthToken($authToken);

		if (!$varsDecoded || !$this->validateHmac($varsDecoded->username, $varsDecoded->timestamp, $varsDecoded->hmac)) {
			throw new \FormatD\HmacAuthentication\Exception('Invalid Auth Token', 1532459848);
		}

		return $varsDecoded;
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