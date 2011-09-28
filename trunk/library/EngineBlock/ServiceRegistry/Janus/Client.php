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

class EngineBlock_ServiceRegistry_Janus_Client extends EngineBlock_Rest_Client
{
    /**
     * The service registry can only be accessed with a proper userid.
     * @var String 
     */
    protected $_user = NULL;
    
    /**
     * A secret needs to be used to sign requests to the service registry.
     * @var String
     */
    protected $_secret = NULL;
    
    public function __construct($url, $user, $secret)
    {
        parent::__construct($url);
        
        $this->_user = $user;
        $this->_secret = $secret;
    }

    public function get($args = array())
    {
        // Sign the request.
        $this->_data["janus_key"]   = $this->_user;
        $this->_data["userid"]      = $this->_user;

        $this->_setSignature();

        return parent::get($args);
    }

    protected function _setSignature()
    {
        // don't sign an old signature if present
        if (isset($this->_data["janus_sig"])) {
            unset($this->_data["janus_sig"]);
        }

        $signatureData = $this->_data;

        // rest=1 will later be added to the request by zend's rest client;
        // we need to make this part of the signature because janus rest
        // will evaluate all params for the sig, even the ones we don't use
        $signatureData['rest'] = 1;

        ksort($signatureData);

        $concatString = '';
        foreach($signatureData AS $key => $value) {
            if (!is_null($value)) { // zend rest will skip null values
                $concatString .= $key . $value;
            }
        }
        $prependSecret = $this->_secret . $concatString;

        $hashString = hash('sha512', $prependSecret);
        $this->_data["janus_sig"] = $hashString;
    }
}
