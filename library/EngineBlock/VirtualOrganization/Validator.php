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

class EngineBlock_VirtualOrganization_Validator
{
    public function isMember($voId, $subjectId, $idp)
    {
        $virtualOrganization = new EngineBlock_VirtualOrganization($voId);
        if ($this->_isMemberOfGroups($virtualOrganization, $subjectId)) {
            return true;
        }
        if ($this->_isMemberOfIdps($virtualOrganization, $idp)) {
            return true;
        }
        return false;
    }

    protected function _isMemberOfGroups(EngineBlock_VirtualOrganization $virtualOrganization, $subjectId)
    {
        $groupProvider = $this->_getGroupProvider($subjectId);

        try {

            $groups = $virtualOrganization->getGroups();

            foreach ($groups as $group) {
                $groupProvider->setGroupStem($group->stem);
                if ($groupProvider->isMember($group->id)) {
                    return true;
                }
            }
        } catch (EngineBlock_VirtualOrganization_VoIdentifierNotFoundException $e) {
            ebLog()->warn($e->getMessage());
        }
        return false;
    }

    protected function _isMemberOfIdps(EngineBlock_VirtualOrganization $virtualOrganization, $idp)
    {
        $voIdps = $virtualOrganization->getIdps();
        foreach ($voIdps as $voIdp) {
            /**
             * @var EngineBlock_VirtualOrganization_Idp $idp
             */
            if ($voIdp === $idp) {
                return true;
            }
        }
        return false;
    }

    protected function _getGroupProvider($subjectId)
    {
        return EngineBlock_Group_Provider_Aggregator_MemoryCacheProxy::createFromConfigFor(
            $subjectId
        );
    }
}