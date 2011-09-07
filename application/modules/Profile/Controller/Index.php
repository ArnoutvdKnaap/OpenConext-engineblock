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

class Profile_Controller_Index extends Default_Controller_LoggedIn
{
    public function indexAction()
    {
        $this->metadata = new EngineBlock_AttributeMetadata();
        $this->aggregator = EngineBlock_Group_Provider_Aggregator_MemoryCacheProxy::createFromConfigFor(
            $this->attributes['nameid'][0]
        );
        $this->groupOauth = $this->user->getUserOauth();

        $serviceRegistryClient = new EngineBlock_ServiceRegistry_Client();
        $this->spList = $serviceRegistryClient->getSpList();

        $this->consent = $this->user->getConsent();

        $this->spOauthList = $this->getSpOauthList($this->spList);
    }

    /**
     * @param $spList all service providers
     * @return all service providers that have an entry in the oauth (consent can be revoked)
     */
    protected function getSpOauthList($spList)
    {
        $oauthList = $this->user->getThreeLeggedShindigOauth();
        $results = array();
        foreach ($spList as $spId => $sp) {
            if (array_key_exists('coin:gadgetbaseurl',$sp)) {
                $pattern = '#' . $sp['coin:gadgetbaseurl'] . '#';
                foreach ($oauthList as $oauth) {
                    if (preg_match($pattern,$oauth)) {
                        $results[$spId] = $oauth;
                    }
                }
            }
        }
        return $results;
    }
}