<?php

namespace OpenConext\EngineBlockBundle\Controller;

use EngineBlock_Corto_ProxyServer;
use OpenConext\EngineBlockBundle\Pdp\PolicyDecision;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Translation\TranslatorInterface;
use Twig_Environment;

/**
 * @SuppressWarnings(PHPMD.TooManyPublicMethods) Mimics the previous methodology, will be refactored
 *  see https://www.pivotaltracker.com/story/show/107565968
 */
class FeedbackController
{
    /**
     * @var TranslatorInterface
     */
    private $translator;

    /**
     * @var Twig_Environment
     */
    private $twig;

    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(
        TranslatorInterface $translator,
        Twig_Environment $twig,
        LoggerInterface $logger
    ) {
        $this->translator = $translator;
        $this->twig = $twig;
        $this->logger = $logger;

        // we have to start the old session in order to be able to retrieve the feedback info
        $server = new EngineBlock_Corto_ProxyServer($twig);
        $server->startSession();
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function unableToReceiveMessageAction()
    {
        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/unable-to-receive-message.html.twig'),
            400
        );
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function sessionLostAction()
    {
        return new Response($this->twig->render('@theme/Authentication/View/Feedback/session-lost.html.twig'), 400);
    }

    /**
     * @param Request $request
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function unknownIssuerAction(Request $request)
    {
        // Add feedback info from url
        $customFeedbackInfo['EntityID'] = $request->get('entity-id');
        $customFeedbackInfo['Destination'] = $request->get('destination');

        $this->setFeedbackInformationOnSession($customFeedbackInfo);

        $body = $this->twig->render('@theme/Authentication/View/Feedback/unknown-issuer.html.twig');

        return new Response($body, 404);
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function noIdpsAction()
    {
        // @todo Send 4xx or 5xx header?

        return new Response($this->twig->render('@theme/Authentication/View/Feedback/no-idps.html.twig'));
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function invalidAcsLocationAction()
    {
        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/invalid-acs-location.html.twig'),
            400
        );
    }

    /**
     * @param Request $request
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function unsupportedSignatureMethodAction(Request $request)
    {
        return new Response(
            $this->twig
                ->render(
                    '@theme/Authentication/View/Feedback/unsupported-signature-method.html.twig',
                    [
                        'signatureMethod' => $request->get('signature-method')
                    ]
                ),
            400
        );
    }

    /**
     * @param Request $request
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function unknownServiceProviderAction(Request $request)
    {
        $entityId = $request->get('entity-id');

        // Add feedback info from url
        $customFeedbackInfo['EntityID'] = $entityId;
        $this->setFeedbackInformationOnSession($customFeedbackInfo);

        $body = $this->twig->render(
            '@theme/Authentication/View/Feedback/unknown-service-provider.html.twig',
            [
                'entityId' => $entityId
            ]
        );

        return new Response($body, 400);
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function missingRequiredFieldsAction()
    {
        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/missing-required-fields.html.twig'),
            400
        );
    }

    /**
     * @SuppressWarnings(PHPMD.Superglobals) This is required to mimic the existing functionality
     *
     * @param Request $request
     * @return Response
     */
    public function customAction()
    {
        $currentLocale = $this->translator->getLocale();

        $title = $this->translator->trans('error_generic');
        $description = $this->translator->trans('error_generic_desc');

        if ($session->has('feedback_custom')) {
            $feedbackCustom = $session->get('feedback_custom');
            if (isset($feedbackCustom['title'][$currentLocale])) {
                $title = $feedbackCustom['title'][$currentLocale];
            }

            if (isset($feedbackCustom['description'][$currentLocale])) {
                $description = $feedbackCustom['description'][$currentLocale];
            }
        }

        return new Response(
            $this->twig->render(
                '@theme/Authentication/View/Feedback/custom.html.twig',
                [
                    'title' => $title,
                    'description' => $description,
                ]
            )
        );
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function invalidAcsBindingAction()
    {
        // @todo Send 4xx or 5xx header depending on invalid binding came from request or configured metadata
        return new Response($this->twig->render('@theme/Authentication/View/Feedback/invalid-acs-binding.html.twig'));
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function receivedErrorStatusCodeAction()
    {
        // @todo Send 4xx or 5xx header?
        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/received-error-status-code.html.twig')
        );
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function signatureVerificationFailedAction()
    {
        // @todo Send 4xx or 5xx header?
        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/received-invalid-signed-response.html.twig')
        );
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function receivedInvalidResponseAction()
    {
        // @todo Send 4xx or 5xx header?
        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/received-invalid-response.html.twig')
        );
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function noConsentAction()
    {
        return new Response($this->twig->render('@theme/Authentication/View/Feedback/no-consent.html.twig'));
    }

    /**
     * @return Response
     * @throws \EngineBlock_Exception
     */
    public function unknownServiceAction()
    {
        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/unknown-service.html.twig'),
            400
        );
    }

    /**
     * @SuppressWarnings(PHPMD.Superglobals) This is required to mimic the existing functionality
     *
     * @param Request $request
     * @return Response
     */
    public function authorizationPolicyViolationAction()
    {
        $locale = $this->translator->getLocale();
        $logo = null;
        $policyDecisionMessage = null;

        if (isset($_SESSION['error_authorization_policy_decision'])) {
            /** @var PolicyDecision $policyDecision */
            $policyDecision = $_SESSION['error_authorization_policy_decision'];

            if ($policyDecision->hasLocalizedDenyMessage()) {
                $policyDecisionMessage = $policyDecision->getLocalizedDenyMessage($locale, 'en');
            } elseif ($policyDecision->hasStatusMessage()) {
                $policyDecisionMessage = $policyDecision->getStatusMessage();
            }
            $logo = $policyDecision->getIdpLogo();
        }


        return new Response(
            $this->twig->render(
                '@theme/Authentication/View/Feedback/authorization-policy-violation.html.twig',
                [
                    'logo' => $logo,
                    'policyDecisionMessage' => $policyDecisionMessage,
                ]
            ),
            400
        );
    }

    /**
     * @param Request $request
     * @return Response
     */
    public function unknownPreselectedIdpAction(Request $request)
    {
        // Add feedback info from url
        $customFeedbackInfo['Idp Hash'] = $request->get('idp-hash');
        $this->setFeedbackInformationOnSession($customFeedbackInfo);

        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/unknown-preselected-idp.html.twig'),
            400
        );
    }

    /**
     * @return Response
     */
    public function stuckInAuthenticationLoopAction()
    {
        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/stuck-in-authentication-loop.html.twig'),
            400
        );
    }

    /**
     * @SuppressWarnings(PHPMD.Superglobals) This is required to mimic the existing functionality
     *
     * @param array $customFeedbackInfo
     */
    private function setFeedbackInformationOnSession(array $customFeedbackInfo)
    {
        if (!isset($_SESSION['feedbackInfo'])) {
            $_SESSION['feedbackInfo'] = [];
        }
        $_SESSION['feedbackInfo'] = array_merge($customFeedbackInfo, $_SESSION['feedbackInfo']);
    }
}
