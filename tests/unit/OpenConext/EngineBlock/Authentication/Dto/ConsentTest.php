<?php

namespace OpenConext\EngineBlock\Authentication\Tests\Dto;

use DateTime;
use OpenConext\Component\EngineBlockMetadata\ContactPerson;
use OpenConext\Component\EngineBlockMetadata\Entity\ServiceProvider;
use OpenConext\EngineBlock\Authentication\Dto\Consent;
use OpenConext\EngineBlock\Authentication\Model\Consent as ConsentModel;
use OpenConext\EngineBlock\Authentication\Value\ConsentType;
use PHPUnit_Framework_TestCase as TestCase;
use SAML2\Constants;

class ConsentTest extends TestCase
{
    private function createServiceProvider()
    {
        $supportContact = new ContactPerson('support');
        $supportContact->givenName = 'givenName';
        $supportContact->surName = 'surName';
        $supportContact->telephoneNumber = '+31612345678';
        $supportContact->emailAddress = 'mail@example.org';

        $serviceProvider = new ServiceProvider('entity-id');
        $serviceProvider->contactPersons[] = $supportContact;

        $serviceProvider->supportUrlNl = 'https://example.org/support-nl';
        $serviceProvider->supportUrlEn = 'https://example.org/support-en';
        $serviceProvider->displayNameEn = 'Display Name EN';
        $serviceProvider->displayNameNl = 'Display Name NL';
        $serviceProvider->termsOfServiceUrl = 'https://example.org/eula';
        $serviceProvider->nameIdFormat = Constants::NAMEID_TRANSIENT;

        return $serviceProvider;
    }

    /**
     * @test
     * @group EngineBlock
     * @group Authentication
     * @group Dto
     */
    public function all_values_are_serialized_to_json()
    {
        $serviceProvider = $this->createServiceProvider();
        $consentGivenOn = new DateTime('20080624 10:00:00');
        $consentType = ConsentType::explicit();

        $consent = new Consent(
            new ConsentModel(
                'user-id',
                'entity-id',
                $consentGivenOn,
                $consentType
            ),
            $serviceProvider
        );

        $json = $consent->jsonSerialize();

        $this->assertEquals($consentGivenOn->format(DateTime::ATOM), $json['consent_given_on']);
        $this->assertEquals($consentType->jsonSerialize(), $json['consent_type']);
        $this->assertArrayHasKey('service_provider', $json);

        $json = $json['service_provider'];

        $this->assertEquals($serviceProvider->entityId, $json['entity_id']);
        $this->assertArrayHasKey('en', $json['support_url']);
        $this->assertArrayHasKey('nl', $json['support_url']);
        $this->assertEquals($serviceProvider->supportUrlEn, $json['support_url']['en']);
        $this->assertEquals($serviceProvider->supportUrlNl, $json['support_url']['nl']);
        $this->assertEquals($serviceProvider->displayNameEn, $json['display_name']['en']);
        $this->assertEquals($serviceProvider->displayNameNl, $json['display_name']['nl']);
        $this->assertEquals($serviceProvider->supportUrlNl, $json['support_url']['nl']);
        $this->assertEquals($serviceProvider->termsOfServiceUrl, $json['eula_url']);
        $this->assertEquals($serviceProvider->contactPersons[0]->emailAddress, $json['support_email']);
        $this->assertEquals($serviceProvider->nameIdFormat, $json['name_id_format']);
    }

    /**
     * @test
     * @group EngineBlock
     * @group Authentication
     * @group Dto
     */
    public function display_name_falls_back_to_name_if_display_name_is_empty()
    {
        $serviceProvider = $this->createServiceProvider();
        $serviceProvider->displayNameEn = '';
        $serviceProvider->displayNameNl = '';
        $serviceProvider->nameEn = 'Name EN';
        $serviceProvider->nameNl = 'Name NL';

        $consentGivenOn = new DateTime();
        $consentType = ConsentType::explicit();

        $consent = new Consent(
            new ConsentModel(
                'user-id',
                'entity-id',
                $consentGivenOn,
                $consentType
            ),
            $serviceProvider
        );

        $json = $consent->jsonSerialize();

        $this->assertArrayHasKey('service_provider', $json);

        $this->assertEquals($serviceProvider->nameEn, $json['service_provider']['display_name']['en']);
        $this->assertEquals($serviceProvider->nameNl, $json['service_provider']['display_name']['nl']);
    }

    /**
     * @test
     * @group EngineBlock
     * @group Authentication
     * @group Dto
     */
    public function display_name_falls_back_to_entity_id_if_name_is_empty()
    {
        $serviceProvider = $this->createServiceProvider();
        $serviceProvider->displayNameEn = '';
        $serviceProvider->displayNameNl = '';
        $serviceProvider->nameEn = '';
        $serviceProvider->nameNl = '';

        $consentGivenOn = new DateTime();
        $consentType = ConsentType::explicit();

        $consent = new Consent(
            new ConsentModel(
                'user-id',
                'entity-id',
                $consentGivenOn,
                $consentType
            ),
            $serviceProvider
        );

        $json = $consent->jsonSerialize();

        $this->assertArrayHasKey('service_provider', $json);

        $this->assertEquals($serviceProvider->entityId, $json['service_provider']['display_name']['en']);
        $this->assertEquals($serviceProvider->entityId, $json['service_provider']['display_name']['nl']);
    }
}
