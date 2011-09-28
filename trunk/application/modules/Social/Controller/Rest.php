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

define('ENGINEBLOCK_FOLDER_SHINDIG', ENGINEBLOCK_FOLDER_LIBRARY.'shindig/php/');
 
class Social_Controller_Rest extends EngineBlock_Controller_Abstract
{
    public function indexAction($url)
    {
        $this->setNoRender(); // let shindig do the rendering

        set_include_path(ENGINEBLOCK_FOLDER_SHINDIG . PATH_SEPARATOR . get_include_path());
        
        include_once('src/common/Config.php');
        include_once('src/common/File.php');

        // You can't inject a Config, so force it to try loading
        // and ignore errors from config file not being there :(
        global $shindigConfig;
        $shindigConfig = array();
        @Config::setConfig(array('allow_plaintext_token'=>true,
                                 'person_service'       => 'EngineBlock_OpenSocial_ShindigService',
                                 'activity_service'     => 'EngineBlock_OpenSocial_ShindigService',
                                 'group_service'        => 'EngineBlock_OpenSocial_ShindigService',
        ));

        spl_autoload_register(array(get_class($this), 'shindigAutoLoad'));
        
        // Shindig expects urls to be moiunted on /social/rest so we enforce that.
        $_SERVER['REQUEST_URI'] = '/social/rest/' . $url;
        // We only support JSON
        $_SERVER['CONTENT_TYPE'] = 'application/json';
        
        // Shindig wants a security token, but interface F in coin is auth-less so we fake one.
        $_REQUEST["st"] = $_GET["st"] = $_POST["st"] = "o:v:a:d:u:m:c";

        $requestMethod = EngineBlock_ApplicationSingleton::getInstance()->getHttpRequest()->getMethod();
        $methodName = 'do' . ucfirst(strtolower($requestMethod));

        $servletInstance = new DataServiceServlet();
        if (is_callable(array($servletInstance, $methodName))) {
            $servletInstance->$methodName();
        }
        else {
            echo "Invalid method";
            // @todo Error out
        }
    }

    public static function shindigAutoLoad($className)
    {
        $locations = array(
            'src/common',
            'src/common/sample',
            'src/gadgets',
            'src/gadgets/servlet',
            'src/gadgets/oauth',
            'src/gadgets/sample',
            'src/social',
            'src/social/servlet',
            'src/social/service',
            'src/social/opensocial',
            'src/social/model',
            'src/social/spi',
            'src/social/converters',
            'src/social/oauth',
            'src/social/sample'
        );
        
        $extensionClassPaths = Config::get('extension_class_paths');
        if (!empty($extensionClassPaths)) {
            $locations = array_merge(explode(',', $extensionClassPaths), $locations);
        }

        // Check for the presence of this class in our all our directories.
        $fileName = $className . '.php';
        foreach ($locations as $path) {
            if (file_exists(ENGINEBLOCK_FOLDER_SHINDIG."{$path}/$fileName")) {
                require $path . '/' . $fileName;
                return true;
            }
        }
        return false;
    }
}
