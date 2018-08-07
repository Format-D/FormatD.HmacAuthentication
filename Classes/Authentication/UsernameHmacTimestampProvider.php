<?php
namespace FormatD\HmacAuthentication\Authentication;


use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\Token\UsernamePassword;
use Neos\Flow\Security\Authentication\Token\UsernamePasswordHttpBasic;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Cryptography\HashService;
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
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames()
    {
        return [UsernameHmacTimestampToken::class];
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

        if (!is_array($credentials) || !isset($credentials['username']) || !isset($credentials['hmac']) || !isset($credentials['timestamp'])) {
            return;
        }

        $providerName = $this->options['mainAuthenticationProviderName'] ? $this->options['mainAuthenticationProviderName'] : $this->name;
        $accountRepository = $this->accountRepository;
        $this->securityContext->withoutAuthorizationChecks(function () use ($credentials, $providerName, $accountRepository, &$account) {
            $account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $providerName);
        });

        $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);

        if ($account === null) {
        	// validate anyway to prevent timing attacks
            $this->hmacService->validateHmac($credentials['username'], $credentials['timestamp'], $credentials['hmac']);
            return;
        }

        if ($this->hmacService->validateHmac($credentials['username'], $credentials['timestamp'], $credentials['hmac'])) {
            $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
        } else {
            $account->authenticationAttempted(TokenInterface::WRONG_CREDENTIALS);
        }
        $this->accountRepository->update($account);
        $this->persistenceManager->whitelistObject($account);
    }
}
