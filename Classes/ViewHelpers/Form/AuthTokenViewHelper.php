<?php
namespace FormatD\HmacAuthentication\ViewHelpers\Form;

use Neos\Flow\Annotations as Flow;

/**
 * Renders an <input type="hidden" ...> tag with an authtoken for hmac authentication.
 *
 * = Examples =
 *
 * <code title="Example">
 * <f:form.hidden accountIdentifier="someUserName" />
 * </code>
 * <output>
 * <input type="hidden" name="__authentication[HmacAuthentication][authToken]" value="*TheAuthToken*" />
 * </output>
 *
 * See <f:form> for more documentation.
 *
 * @api
 */
class AuthTokenViewHelper extends \Neos\FluidAdaptor\ViewHelpers\Form\AbstractFormFieldViewHelper
{

	/**
	 * @Flow\Inject
	 * @var \FormatD\HmacAuthentication\Service\HmacService
	 */
	protected $hmacService;

    /**
     * @var string
     */
    protected $tagName = 'input';

    /**
     * Initialize the arguments.
     *
     * @return void
     * @api
     */
    public function initializeArguments()
    {
		// this form field needs no other arguments
    }

    /**
     * Renders a hidden field with authToken.
     *
	 * @param string $accountIdentifier
     * @return string
     * @api
     */
    public function render($accountIdentifier)
    {
        $name = '__authentication[HmacAuthentication][authToken]';
        $this->registerFieldNameForFormTokenGeneration($name);

        $this->tag->addAttribute('type', 'hidden');
        $this->tag->addAttribute('name', $name);
        $this->tag->addAttribute('value', $this->hmacService->encodeAuthToken($accountIdentifier));

        $this->addAdditionalIdentityPropertiesIfNeeded();
        $this->setErrorClassAttribute();

        return $this->tag->render();
    }
}
