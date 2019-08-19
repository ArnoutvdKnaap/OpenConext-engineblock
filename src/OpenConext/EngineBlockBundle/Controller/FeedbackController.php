<?php

namespace OpenConext\EngineBlockBundle\Controller;

use EngineBlock_Corto_ProxyServer;
use OpenConext\EngineBlockBundle\Exception\RuntimeException;
use OpenConext\EngineBlockBundle\Pdp\PolicyDecision;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Translation\TranslatorInterface;
use Twig_Environment;
use Twig_Error_Loader;

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

    public function feedbackAction(Request $request)
    {
        $pageIdentifier = $request->get('identifier');
        $statusCode = $request->get('error_code');
        $template = $this->getTemplateNameByIdentifier($pageIdentifier);

        return new Response(
            $this->twig->render($template),
            $statusCode
        );
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

        $this->setFeedbackInformationOnSession($request->getSession(), $customFeedbackInfo);

        $body = $this->twig->render('@theme/Authentication/View/Feedback/unknown-issuer.html.twig');

        return new Response($body, 404);
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
        $this->setFeedbackInformationOnSession($request->getSession(), $customFeedbackInfo);

        $body = $this->twig->render(
            '@theme/Authentication/View/Feedback/unknown-service-provider.html.twig',
            [
                'entityId' => $entityId
            ]
        );

        return new Response($body, 400);
    }

    /**
     * @param Request $request
     * @return Response
     */
    public function invalidAttributeValueAction(Request $request)
    {
        $feedbackInfo = $request->getSession()->get('feedbackInfo');

        $attributeName = $feedbackInfo['attributeName'];
        $attributeValue = $feedbackInfo['attributeValue'];

        return new Response(
            $this->twig->render(
                '@theme/Authentication/View/Feedback/invalid-attribute-value.html.twig',
                [
                    'attributeName' => $attributeName,
                    'attributeValue' => $attributeValue,
                ]
            ),
            403
        );
    }

    /**
     * @param Request $request
     * @return Response
     */
    public function customAction(Request $request)
    {
        $currentLocale = $this->translator->getLocale();

        $title = $this->translator->trans('error_generic');
        $description = $this->translator->trans('error_generic_desc');

        $session = $request->getSession();
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
     * @param Request $request
     * @return Response
     */
    public function authorizationPolicyViolationAction(Request $request)
    {
        $locale = $this->translator->getLocale();
        $logo = null;
        $policyDecisionMessage = null;

        $session = $request->getSession();
        if ($session->has('error_authorization_policy_decision')) {
            /** @var PolicyDecision $policyDecision */
            $policyDecision = $session->get('error_authorization_policy_decision');

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
        $this->setFeedbackInformationOnSession($request->getSession(), $customFeedbackInfo);

        return new Response(
            $this->twig->render('@theme/Authentication/View/Feedback/unknown-preselected-idp.html.twig'),
            400
        );
    }

    /**
     * @return Response
     */
    public function noAuthenticationRequestReceivedAction(Request $request)
    {
        // The exception message is used on the error page. As mostly developers or other tech-savvy people will see
        // this message. The ExceptionListener is responsible for setting the message on the feedback_custom field.
        $session = $request->getSession();
        if ($session->has('feedback_custom')) {
            $message = $session->get('feedback_custom');
        } else {
            // This should never occur, when it does, this error page is called from outside the application context
            // or the exception that shows this page was triggered elsewhere in code without a message.
            $message = 'More elaborate error details could not be found..';
        }

        return new Response(
            $this->twig->render(
                '@theme/Authentication/View/Feedback/no-authentication-request-received.html.twig',
                [
                    'message' => $message,
                ]
            ),
            400
        );
    }

    /**
     * @param SessionInterface $session
     * @param array $customFeedbackInfo
     */
    private function setFeedbackInformationOnSession(SessionInterface $session, array $customFeedbackInfo)
    {
        $feedbackInfo = $session->get('feedbackInfo', []);
        $session->set('feedbackInfo', array_merge($customFeedbackInfo, $feedbackInfo));
    }

    private function getTemplateNameByIdentifier($pageIdentifier)
    {
        $templateName = sprintf('@theme/Authentication/View/Feedback/%s.html.twig', $pageIdentifier);
        try {
            $this->twig->loadTemplate($templateName);
        } catch (Twig_Error_Loader $e) {
            // The template does not exist
            throw new RuntimeException(
                sprintf(
                    'The requested error template "%s" can not be loaded. Please review the feedback.yml route configuration.',
                    $templateName
                )
            );
        }
        return $templateName;
    }
}
