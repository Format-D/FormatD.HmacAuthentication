
# FormatD.HmacAuthentication

This package adds an authentication provider for authenticating a flow account using a token with a configurable timeout.
Authentication is done by passing username, timestamp and a hmac. For generating this token the package contains some viewhelpers and a Service.

Keep in mind: The token is usable multiple times and does not invalidate after usage. Only after a timeout.

## Configure the Authentication Provider

In addition to your usual PersistedUsernamePasswordProvider you have to add a second UsernameHmacTimestampProvider provider to the configuration. 
Set the providerOption "mainAuthenticationProviderName" to the name of your PersistedUsernamePasswordProvider so that only the accounts of this provider can use the magic links.

```
Neos:
  Flow:
    security:
      authentication:
        providers:
          'HmacProvider':
            provider: 'FormatD\HmacAuthentication\Authentication\UsernameHmacTimestampProvider'
            providerOptions:
              # For an account with this authentication provider name will be searched:
              mainAuthenticationProviderName: 'My.Website:FrontendLoginProvider'
            entryPoint: 'WebRedirect'
            entryPointOptions:
              routeValues:
                '@package': 'My.Website'
                '@controller': 'Authentication'
                '@action': 'index'
```

## Authentication on button click:


```
{namespace hmacauth=FormatD\HmacAuthentication\ViewHelpers}

<f:form package="myPackage" action="login" controller="authentication">
	<hmacauth:form.authToken accountIdentifier="anyAccountIdentifierYouWantToAuthenticate" />
	<f:form.submit name="login" value="login" />
</f:form>
```

## Authentication with a link (not encouraged):

### Be Aware!
This is a very dangerous way to do authentication as the login-link is tracked for example in server logfiles or cached in proxies. Setting the timeout as low as possible is a must.
Always prefer the submit button solution mentioned above.

### OK, let me do this anyway
There are two ways how to generate a authentication link: 
Use one of the ViewHelpers...

```
{namespace hmacauth=FormatD\HmacAuthentication\ViewHelpers}
<hmacauth:link.authenticatedAction action="myAction" controller="MyController">Login to MyWebsite</f:link.authenticatedAction>
```
```
{namespace hmacauth=FormatD\HmacAuthentication\ViewHelpers}
<hmacauth:uri.authenticatedAction action="myAction" controller="MyController" />
```
...or use the hmacService directly in your code:
```

	/**
	 * @Flow\Inject
	 * @var \FormatD\HmacAuthentication\Service\HmacService
	 */
	protected $hmacService;

	public function myFunction() {
	    // ...
		$theUserName = 'username';
		$loginLinkQueryPart = $this->hmacService->generateHmacAuthenticationQueryStringPart($theUserName);
		// ...
	}

```

## Using only AuthToken:

If you want to use the authToken in your code (for example to authenticate something else) just use the service class

```
	$authToken = $this->hmacService->encodeAuthToken($theUserName);
	
	$timestampIdentifierAndHmac = $this->hmacService->decodeAndValidateAuthToken($authToken);
```



