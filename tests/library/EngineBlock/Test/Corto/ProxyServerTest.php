<?php
use OpenConext\Component\EngineBlockMetadata\Entity\IdentityProvider;
use OpenConext\Component\EngineBlockMetadata\MetadataRepository\InMemoryMetadataRepository;

/**
 * Note: this Test only tests setting of NameIDFormat, add other tests if required
 */
class EngineBlock_Test_Corto_ProxyServerTest extends PHPUnit_Framework_TestCase
{
    public function testNameIDFormatIsNotSetByDefault()
    {
        $expectedNameIdPolicy = [
            'AllowCreate' => true
        ];

        $proxyServer = $this->factoryProxyServer();

        $originalRequest = $this->factoryOriginalRequest();
        $identityProvider = $proxyServer->getRepository()->fetchIdentityProviderByEntityId('testIdp');
        /** @var SAML2_AuthnRequest $enhancedRequest */
        $enhancedRequest = EngineBlock_Saml2_AuthnRequestFactory::createFromRequest(
            $originalRequest,
            $identityProvider,
            $proxyServer
        );

        $actualNameIdPolicy = $enhancedRequest->getNameIdPolicy();

        $this->assertSame($expectedNameIdPolicy, $actualNameIdPolicy);
    }

    public function testNameIDFormatIsSetFromRemoteMetaData()
    {
        $proxyServer = $this->factoryProxyServer();
        $originalRequest = $this->factoryOriginalRequest();

        $identityProvider = $proxyServer->getRepository()->fetchIdentityProviderByEntityId('testIdp');
        $identityProvider->nameIdFormat = 'fooFormat';

        /** @var SAML2_AuthnRequest $enhancedRequest */
        $enhancedRequest = EngineBlock_Saml2_AuthnRequestFactory::createFromRequest(
            $originalRequest,
            $identityProvider,
            $proxyServer
        );

        $nameIdPolicy = $enhancedRequest->getNameIdPolicy();
        $this->assertEquals($nameIdPolicy['Format'], 'fooFormat');
    }

    /**
     * @return array
     */
    private function factoryOriginalRequest()
    {
        $originalRequest = new EngineBlock_Saml2_AuthnRequestAnnotationDecorator(new SAML2_AuthnRequest());

        return $originalRequest;
    }


    private function factoryProxyServer()
    {
        $proxyServer = new EngineBlock_Corto_ProxyServer();
        $proxyServer->setHostName('test-host');

        $proxyServer->setRepository(new InMemoryMetadataRepository(
            array(new IdentityProvider('testIdp')),
            array()
        ));

        return $proxyServer;
    }
}
