<?php
/**
 * SURFconext EngineBlock
 *
 * LICENSE
 *
 * Copyright 2011 SURFnet bv, The Netherlands
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 *
 * @category  SURFconext EngineBlock
 * @package
 * @copyright Copyright © 2010-2011 SURFnet SURFnet bv, The Netherlands (http://www.surfnet.nl)
 * @license   http://www.apache.org/licenses/LICENSE-2.0  Apache License 2.0
 */

require_once(dirname(__FILE__) . '/../../autoloading.inc.php');
require_once 'PHPUnit/Framework/TestCase.php';

require_once 'RestClientMock.php';


// TODO: replace the calls with a mock rest server, currently tests against
// actual content in Ivo's janus db.

/**
 * EngineBlock_ServiceRegistry test case.
 */
class EngineBlock_ServiceRegistryTest extends PHPUnit_Framework_TestCase 
{
    
    /**
     * @var EngineBlock_ServiceRegistry_Client
     */
    private $EngineBlock_ServiceRegistry;
    
    /**
     * Prepares the environment before running a test.
     */
    protected function setUp() 
    {
        parent::setUp ();
        
        // TODO Auto-generated ServiceRegistryTest::setUp()
        

        $this->EngineBlock_ServiceRegistry = new EngineBlock_ServiceRegistry_Client(/* parameters */);
        $this->EngineBlock_ServiceRegistry->setRestClient(new RestClientMock());
    }
    
    /**
     * Cleans up the environment after running a test.
     */
    protected function tearDown() 
    {
        // TODO Auto-generated ServiceRegistryTest::tearDown()
        

        $this->EngineBlock_ServiceRegistry = null;
        
        parent::tearDown ();
    }
    
    /**
     * Constructs the test case.
     */
    public function __construct() 
    {
        // TODO Auto-generated constructor
    }
    
    /**
     * Tests EngineBlock_ServiceRegistry->getMetadata()
     */
    public function testGetMetadata() 
    {
        
       $result = $this->EngineBlock_ServiceRegistry->getMetadata("http://ivotestsp.local");
       $this->assertTrue(is_array($result));
       $this->assertEquals("A description", $result["description:en"]);
    }
    
    public function testGetMetaDataForKey() 
    {
        
        $result = $this->EngineBlock_ServiceRegistry->getMetaDataForKey("http://ivotestsp.local", "certData");
        $this->assertTrue(is_string($result));    
        $this->assertEquals("aaaaabbbbb", $result);    
    }
    
    public function testGetMetaDataForKeys() 
    {
        $result = $this->EngineBlock_ServiceRegistry->getMetaDataForKeys("http://ivotestsp.local", array("name:en", "description:en"));
        $this->assertEquals(2, count($result));
        $this->assertEquals("Ivo's SP", $result["name:en"]);
        $this->assertEquals("A description", $result["description:en"]);
    }
    
    public function testIsConnectionAllowed() 
    {
        $result = $this->EngineBlock_ServiceRegistry->isConnectionAllowed("http://ivotestsp.local", "http://doesntexist.local");
        $this->assertFalse($result);
        
        $result = $this->EngineBlock_ServiceRegistry->isConnectionAllowed("http://ivotestsp.local", "http://ivoidp");
        $this->assertTrue($result);
    }
    
    public function testGetArp()
    {
        $result = $this->EngineBlock_ServiceRegistry->getArp("http://ivotestsp.local");
        $this->assertEquals(3, count($result));
        $this->assertEquals("someArp", $result["name"]);
        $this->assertEquals(4, count($result["attributes"]));
        $this->assertEquals("sn", $result["attributes"][0]);
    
    }
    
    public function testFindIdentifiersByMetadata()
    {
        $result = $this->EngineBlock_ServiceRegistry->findIdentifiersByMetadata("url:en", "www.google.com");
        $this->assertEquals(1, count($result));
        $this->assertEquals("http://ivotestsp.local", $result[0]);
      
    }
    
    public function testGetIdpList()
    {
        $result = $this->EngineBlock_ServiceRegistry->getIdpList();
        
        $this->assertEquals(2, count($result));
        $this->assertEquals("Ivo's IDP", $result["http://ivotestidp.local"]["name:en"]);
        
        $result = $this->EngineBlock_ServiceRegistry->getIdpList(array(), "someSP");
        $this->assertEquals(1, count($result), "Idplist not correctly filtered by SP");

        $result = $this->EngineBlock_ServiceRegistry->getIdpList(array(), NULL);
        $this->assertEquals(2, count($result), "Idplist not correctly ignoring NULL sp");
        
        
    }
    
    public function testGetSpList()
    {
        $result = $this->EngineBlock_ServiceRegistry->getSpList();
        $this->assertEquals(2, count($result));
        $this->assertEquals("Ivo's SP", $result["http://ivotestsp.local"]["name:en"]);
    }
}

