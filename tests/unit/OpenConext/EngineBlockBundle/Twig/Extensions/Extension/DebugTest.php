<?php

/**
 * Copyright 2010 SURFnet B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace OpenConext\EngineBlockBundle\Twig\Extensions\Extension;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

class DebugTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * @var Debug
     */
    private $debug;

    protected function setUp()
    {
        $this->debug = new Debug();
    }

    public function testPrintHumanReadable()
    {
        $output = $this->debug->printHumanReadable(['testString']);
        $this->assertContains('[0] => testString', $output);
    }

    public function testVarExport()
    {
        $output = $this->debug->varExport('testString');
        $this->assertContains('testString', $output);

        $output = $this->debug->varExport(['testString']);
        $this->assertContains('0 => \'testString\'', $output);
    }
}
