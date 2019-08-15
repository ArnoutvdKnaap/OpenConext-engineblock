<?php

/**
 * Copyright 2018 SURFnet B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace OpenConext\EngineBlockBundle\Twig\Extensions\Extension;

use EngineBlock_ApplicationSingleton;
use OpenConext\EngineBlockBundle\Configuration\ErrorFeedbackConfiguration;
use OpenConext\EngineBlockBundle\Configuration\ErrorFeedbackConfigurationInterface;
use OpenConext\EngineBlockBundle\Configuration\WikiLink;
use OpenConext\EngineBlockBundle\Value\FeedbackInformation;
use OpenConext\EngineBlockBundle\Value\FeedbackInformationMap;
use Twig\TwigFunction;
use Twig_Extension;

class Feedback extends Twig_Extension
{
    /**
     * @var EngineBlock_ApplicationSingleton
     */
    private $application;

    /**
     * @var ErrorFeedbackConfigurationInterface
     */
    private $errorFeedbackConfiguration;

    public function __construct(
        EngineBlock_ApplicationSingleton $application,
        ErrorFeedbackConfigurationInterface $errorFeedbackConfiguration
    )
    {
        $this->application = $application;
        $this->errorFeedbackConfiguration = $errorFeedbackConfiguration;
    }

    public function getFunctions()
    {
        return [
            new TwigFunction('feedbackInfo', [$this, 'getFeedbackInfo']),
            new TwigFunction('flushLog', [$this, 'flushLog']),
            new TwigFunction('hasWikiLink', [$this, 'hasWikiLink']),
            new TwigFunction('getWikiLink', [$this, 'getWikiLink']),
        ];
    }

    public function flushLog($message)
    {
        // For now use the EngineBlock_ApplicationSingleton to flush the log
        $this->application->flushLog($message);
    }

    /**
     * @return FeedbackInformationMap
     */
    public function getFeedbackInfo()
    {
        return $this->retrieveFeedbackInfo();
    }

    /**
     * @param string $templateName
     * @return bool
     */
    public function hasWikiLink($templateName)
    {
        $pageIdentifier = $this->convertTemplateName($templateName);
        return $this->errorFeedbackConfiguration->hasWikiLink($pageIdentifier);
    }

    /**
     * @param string $templateName
     * @return WikiLink
     */
    public function getWikiLink($templateName)
    {
        $pageIdentifier = $this->convertTemplateName($templateName);
        return $this->errorFeedbackConfiguration->getWikiLink($pageIdentifier);
    }

    /**
     * Loads the feedbackInfo from the session and filters out empty valued entries.
     *
     * @return FeedbackInformationMap
     */
    private function retrieveFeedbackInfo()
    {
        $feedbackInfo = $this->application->getSession()->get('feedbackInfo');

        $feedbackInfoMap = new FeedbackInformationMap();

        // Remove the empty valued feedback info entries.
        if (!empty($feedbackInfo)) {
            foreach ($feedbackInfo as $key => $value) {
                if (empty($value)) {
                    unset($feedbackInfo[$key]);
                    continue;
                }
                $feedbackInfoMap->add(new FeedbackInformation($key, $value));
            }
        }

        $feedbackInfoMap->sort();

        return $feedbackInfoMap;
    }

    private function convertTemplateName($templateName)
    {
        $template = end(explode('/', $templateName));
        $stripped = array_shift(explode('.', $template));
        $convertedDashes = str_replace('-', '_', $stripped);
        return $convertedDashes;
    }
}
