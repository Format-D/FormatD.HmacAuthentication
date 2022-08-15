<?php
namespace FormatD\HmacAuthentication\Authentication;


use FormatD\HmacAuthentication\Domain\Model\HmacToken;
use FormatD\HmacAuthentication\Service\HmacService;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\TokenAndProviderFactoryInterface;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

/**
 * An authentication provider that authenticates
 * FormatD\HmacAuthentication\Authentication\UsernameHmacTimestampToken tokens.
 * The accounts are stored in the Content Repository.
 */
class UsernameHmacTimestampProvider extends \Neos\Flow\Security\Authentication\Provider\AbstractProvider
{
    /**
     * @var AccountRepository
     * @Flow\Inject
     */
    protected $accountRepository;

    /**
     * @var \FormatD\HmacAuthentication\Service\HmacService
     * @Flow\Inject
     */
    protected $hmacService;

    /**
     * @Flow\Inject
     * @var TokenAndProviderFactoryInterface
     */
    protected $tokenAndProviderFactory;

    /**
     * @var Context
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @var \Neos\Flow\Persistence\PersistenceManagerInterface
     * @Flow\Inject
     */
    protected $persistenceManager;

    /**
     * @Flow\InjectConfiguration(package="FormatD.HmacAuthentication.allowedAuthenticationProviders")
     * @var array
     */
    protected $allowedAuthenticationProviders;

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames()
    {
        return [UsernameHmacTimestampToken::class];
    }

    /**
     * @param string $alias
     * @return false|string
     */
    protected function getAuthenticationProviderNameByAlias($alias) {
        if(!is_array($this->allowedAuthenticationProviders)) {
            return false;
        }
        if(!key_exists($alias, $this->allowedAuthenticationProviders)) {
            return false;
        }
        $name = $this->allowedAuthenticationProviders[$alias];
        return strlen($name) > 0 ? $name : false;
    }

    /**
     * @param HmacToken $hmacToken
     */
    protected function getAuthenticationProviderNameWithHmacToken($hmacToken) {
        if($hmacToken->hasPayloadEntry(HmacService::HTK_Provider)) {
            $tokenAuthenticationProviderAlias = $hmacToken->getPayloadEntry(HmacService::HTK_Provider);
            if($authenticationProviderName = $this->getAuthenticationProviderNameByAlias($tokenAuthenticationProviderAlias)) {
                return $authenticationProviderName;
            }
        }

        return $this->options['mainAuthenticationProviderName'] ? $this->options['mainAuthenticationProviderName'] : $this->name;
    }

    /**
     * @param HmacToken $hmacToken
     * @return mixed
     */
    protected function getUsernameFromHmacToken($hmacToken) {
        return $hmacToken->getPayloadEntry(HmacService::HTK_Username);
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @return void
     * @throws UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {

        if (!($authenticationToken instanceof UsernameHmacTimestampToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1512771387);
        }

        /** @var $account Account */
        $account = null;
        $credentials = $authenticationToken->getCredentials();

        if ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
        }

        if (!is_array($credentials) || !isset($credentials[UsernameHmacTimestampToken::CRED_TOKEN])) {
            return;
        }

        $hmacToken = HmacToken::FromJson($credentials[UsernameHmacTimestampToken::CRED_TOKEN]);

        $providerName = $this->getAuthenticationProviderNameWithHmacToken($hmacToken);
        $userName = $this->getUsernameFromHmacToken($hmacToken);

        $accountRepository = $this->accountRepository;
        $this->securityContext->withoutAuthorizationChecks(function () use ($credentials, $userName, $providerName, $accountRepository, &$account) {
            $account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($userName, $providerName);
        });

        $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);

        $isHmacTokenValid = $this->hmacService->validateToken($hmacToken);

        if ($account === null) {
            // Return after token hmac validation to prevent timing attacks
            return;
        }

        if ($isHmacTokenValid) {
            if (!isset($this->options['trackAuthenticationAttempts']) || $this->options['trackAuthenticationAttempts'] === true || $this->options['trackAuthenticationAttempts'] === 'successful') {
                $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            }
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
        } else if (!isset($this->options['trackAuthenticationAttempts']) || $this->options['trackAuthenticationAttempts'] === true || $this->options['trackAuthenticationAttempts'] === 'failed') {
            $account->authenticationAttempted(TokenInterface::WRONG_CREDENTIALS);
        }

        $this->accountRepository->update($account);
        $this->persistenceManager->allowObject($account);
    }
}
