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

/**
 * Routes /authorization/ urls
 */
class EngineBlock_Router_Authentication extends EngineBlock_Router_Default
{
    const DEFAULT_MODULE_NAME = 'Authentication';

    protected $_controllerMapping = array(
        'Idp'   =>'IdentityProvider',
        'Sp'    =>'ServiceProvider',
    );

    public function route($uri)
    {
        parent::route($uri);
        // Only route /authentication/ urls
        return ($this->_moduleName === self::DEFAULT_MODULE_NAME);
    }

    public function getControllerName()
    {
        if (isset($this->_controllerMapping[$this->_controllerName])) {
            return $this->_controllerMapping[$this->_controllerName];
        }

        return $this->_controllerName;
    }
}
