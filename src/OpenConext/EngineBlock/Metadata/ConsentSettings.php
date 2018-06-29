<?php

namespace OpenConext\EngineBlock\Metadata;

use JsonSerializable;

/**
 * Value object for IDP consent settings.
 *
 * @package OpenConext\EngineBlock\Metadata
 */
class ConsentSettings implements JsonSerializable
{
    const CONSENT_DISABLED = 'no_consent';
    const CONSENT_MINIMAL = 'minimal_consent';
    const CONSENT_DEFAULT = 'default_consent';

    /**
     * @var array
     */
    private $settings = [];

    /**
     * @var MultilingualValue[]
     */
    private $explanations = [];

    /**
     * @param array $settings
     */
    public function __construct(array $settings = array())
    {
        foreach ($settings as $values) {
            $setting = (object) $values;
            $this->explanations[$setting->name] = $this->extractExplanations($setting);
            $this->settings[] = $setting;
        }
    }

    /**
     * @return array
     */
    public function getSpEntityIdsWithoutConsent()
    {
        return array_filter(
            array_map(
                function ($settings) {
                    if ($settings->type === self::CONSENT_DISABLED) {
                        return $settings->name;
                    }
                },
                $this->settings
            )
        );
    }

    /**
     * @param string $entityId
     * @return bool
     */
    public function isEnabled($entityId)
    {
        $settings = $this->findSettingsFor($entityId);
        if ($settings !== null) {
            return $settings->type !== self::CONSENT_DISABLED;
        }

        return true;
    }

    /**
     * @param string $entityId
     * @return bool
     */
    public function isMinimal($entityId)
    {
        $settings = $this->findSettingsFor($entityId);
        if ($settings !== null) {
            return $settings->type === self::CONSENT_MINIMAL;
        }

        return false;
    }

    public function hasConsentExplanation($entityId)
    {
        return isset($this->explanations[$entityId]);
    }

    /**
     * @param string $entityId
     * @return array
     */
    public function getConsentExplanations($entityId)
    {
        if ($this->hasConsentExplanation($entityId)) {
            return $this->explanations[$entityId];
        }
        return [];
    }

    /**
     * @param string $language
     * @param string $entityId
     * @return bool
     */
    public function hasConsentExplanationIn($language, $entityId)
    {
        if ($this->hasConsentExplanation($entityId)) {
            $explanations = $this->getConsentExplanations($entityId);
            return isset($explanations[$language]);
        }
        return false;
    }

    /**
     * @param string $language
     * @param string $entityId
     * @return string
     */
    public function getConsentExplanationIn($language, $entityId)
    {
        if ($this->hasConsentExplanationIn($language, $entityId)) {
            $explanations = $this->getConsentExplanations($entityId);
            return $explanations[$language]->getValue();
        }
        return '';
    }

    /**
     * @param string $entityId
     */
    private function findSettingsFor($entityId)
    {
        foreach ($this->settings as $values) {
            if ($values->name !== $entityId) {
                continue;
            }

            return $values;
        }
    }

    /**
     * @return array
     */
    public function jsonSerialize()
    {
        return $this->settings;
    }

    /**
     * @param object $setting
     * @return MultilingualValue[]
     */
    private function extractExplanations($setting)
    {
        $fieldNames = get_object_vars($setting);
        $explanationFieldNames = preg_grep('/^explanation:/', array_keys($fieldNames));

        // The explanations will be pulled from the settings object and turned into a multi lang array of explanations.
        $multilingualValues = array_map(
            function ($langField) use ($setting) {
                $langCode = explode(':', $langField)[1];
                return new MultilingualValue($setting->$langField, $langCode);
            },
            $explanationFieldNames
        );

        // Index the explanations array on the language
        $explanations = [];
        foreach ($multilingualValues as $explanation) {
            $explanations[$explanation->getLanguage()] = $explanation;
        }
        return $explanations;
    }
}
