<?php
namespace FormatD\HmacAuthentication\ViewHelpers\Uri;

/*
 * This file is part of the FormatD.HmacAuthentication package.
 *
 */

use Neos\Flow\Mvc\ActionRequest;
use Neos\FluidAdaptor\Core\ViewHelper\AbstractViewHelper;
use Neos\FluidAdaptor\Core\ViewHelper;
use Neos\Flow\Annotations as Flow;

/**
 * A view helper for creating URIs to actions.
 *
 * = Examples =
 *
 * <code title="Defaults">
 * <f:uri.authenticatedAction />
 * </code>
 * <output>
 * currentpackage/currentcontroller?__authentication[HmacAuthentication][authToken]=*credentialsForAuthentication*
 * (depending on routing setup and current package/controller/action)
 * </output>
 *
 * <code title="Additional arguments">
 * <f:uri.authenticatedAction action="myAction" controller="MyController" package="YourCompanyName.MyPackage" subpackage="YourCompanyName.MySubpackage" arguments="{key1: 'value1', key2: 'value2'}" />
 * </code>
 * <output>
 * mypackage/mycontroller/mysubpackage/myaction?key1=value1&amp;key2=value2&__authentication[HmacAuthentication][authToken]=*credentialsForAuthentication*
 * (depending on routing setup)
 * </output>
 *
 * @api
 */
class AuthenticatedActionViewHelper extends AbstractViewHelper
{

    /**
     * @Flow\Inject
     * @var \FormatD\HmacAuthentication\Service\HmacService
     */
    protected $hmacService;

    /**
     * Initialize arguments
     *
     * @return void
     * @api
     */
    public function initializeArguments()
    {
        $this->registerArgument('action', 'string', 'Target action', true);
        $this->registerArgument('arguments', 'array', 'Arguments', false, []);
        $this->registerArgument('controller', 'string', 'Target controller. If NULL current controllerName is used', false, null);
        $this->registerArgument('package', 'string', 'Target package. if NULL current package is used', false, null);
        $this->registerArgument('subpackage', 'string', 'Target subpackage. if NULL current subpackage is used', false, null);
        $this->registerArgument('section', 'string', 'The anchor to be added to the URI', false, '');
        $this->registerArgument('format', 'string', 'The requested format, e.g. ".html"', false, '');
        $this->registerArgument('additionalParams', 'array', 'additional query parameters that won\'t be prefixed like $arguments (overrule $arguments)', false, []);
        $this->registerArgument('absolute', 'boolean', 'By default this ViewHelper renders links with absolute URIs. If this is false, a relative URI is created instead', false, false);
        $this->registerArgument('addQueryString', 'boolean', 'If set, the current query parameters will be kept in the URI', false, false);
        $this->registerArgument('argumentsToBeExcludedFromQueryString', 'array', 'arguments to be removed from the URI. Only active if $addQueryString = true', false, []);
        $this->registerArgument('useParentRequest', 'boolean', 'If set, the parent Request will be used instead of the current one. Note: using this argument can be a sign of undesired tight coupling, use with care', false, false);
        $this->registerArgument('useMainRequest', 'boolean', 'If set, the main Request will be used instead of the current one. Note: using this argument can be a sign of undesired tight coupling, use with care', false, false);
        $this->registerArgument('accountIdentifier', 'string', 'accountIdentifier to authenticate with', true);
    }

    /**
     * Render the Uri.
     *
     * @return string The rendered link
     * @throws ViewHelper\Exception
     * @api
     */
    public function render()
    {
        $uriBuilder = $this->controllerContext->getUriBuilder();
        if ($this->arguments['useParentRequest'] === true) {
            $request = $this->controllerContext->getRequest();
            if ($request->isMainRequest()) {
                throw new ViewHelper\Exception('You can\'t use the parent Request, you are already in the MainRequest.', 1360590758);
            }
            $parentRequest = $request->getParentRequest();
            if (!$parentRequest instanceof ActionRequest) {
                throw new ViewHelper\Exception('The parent requests was unexpectedly empty, probably the current request is broken.', 1565948254);
            }

            $uriBuilder = clone $uriBuilder;
            $uriBuilder->setRequest($parentRequest);
        } elseif ($this->arguments['useMainRequest'] === true) {
            $request = $this->controllerContext->getRequest();
            if (!$request->isMainRequest()) {
                $uriBuilder = clone $uriBuilder;
                $uriBuilder->setRequest($request->getMainRequest());
            }
        }

        $uriBuilder
            ->reset()
            ->setSection($this->arguments['section'])
            ->setCreateAbsoluteUri($this->arguments['absolute'])
            ->setArguments($this->arguments['additionalParams'])
            ->setAddQueryString($this->arguments['addQueryString'])
            ->setArgumentsToBeExcludedFromQueryString($this->arguments['argumentsToBeExcludedFromQueryString'])
            ->setFormat($this->arguments['format']);
        try {
            $uri = $uriBuilder->uriFor($this->arguments['action'], $this->arguments['arguments'], $this->arguments['controller'], $this->arguments['package'], $this->arguments['subpackage']);
        } catch (\Exception $exception) {
            throw new ViewHelper\Exception($exception->getMessage(), $exception->getCode(), $exception);
        }

        $authenticationQueryPart = $this->hmacService->generateHmacAuthenticationQueryStringPart($this->arguments['accountIdentifier']);
        $uri = $uri . (strpos($uri, '?') === FALSE ? '?' : '&' ) . $authenticationQueryPart;

        return $uri;
    }
}
