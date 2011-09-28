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

abstract class OpenSocial_Rest_Mapper_Json_Abstract
    implements OpenSocial_Rest_Mapper_Interface
{
    public function map($responseBody)
    {
        $data = json_decode($responseBody);

        if (isset($data->entry)) {
            if (!is_array($data->entry)) {
                return array($this->_mapEntryToModel($data->entry));
            }
            else {
                $groups = array();
                foreach ($data->entry as $entry) {
                    $groups[] = $this->_mapEntryToModel($entry);
                }
                return $groups;
            }
        }

        throw new OpenSocial_Rest_Exception("No entry / entries found in response?");
    }

    abstract protected function _mapEntryToModel(stdClass $entry);

    protected function _copyEntryPropertiesToModel(stdClass $entry, OpenSocial_Model_Interface $model)
    {
        foreach ($entry as $key => $value) {
            if (property_exists($model, $key)) {
                $model->$key = $value;
            }
        }
        return $model;
    }
}