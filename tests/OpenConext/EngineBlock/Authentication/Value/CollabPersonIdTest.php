<?php

namespace OpenConext\EngineBlock\Authentication\Value;

use EngineBlock_UserDirectory;
use OpenConext\EngineBlock\Exception\InvalidArgumentException;
use PHPUnit_Framework_TestCase as UnitTest;

class CollabPersonIdTest extends UnitTest
{
    /**
     * @test
     * @group EngineBlock
     * @group Authentication
     * @dataProvider \OpenConext\TestDataProvider::notStringOrEmptyString
     *
     * @param mixed $notStringOrEmptyString
     */
    public function collab_person_id_must_be_a_non_empty_string($notStringOrEmptyString)
    {
        $this->expectException(InvalidArgumentException::class);

        new CollabPersonId($notStringOrEmptyString);
    }

    /**
     * @test
     * @group        EngineBlock
     * @group        Authentication
     * @dataProvider invalidNameSpaceProvider
     *
     * @param string $wronglyNamespaced
     */
    public function collab_person_id_must_start_with_the_correct_namespace($wronglyNamespaced)
    {
        $this->expectException(InvalidArgumentException::class);

        new CollabPersonId($wronglyNamespaced);
    }

    /**
     * @return array
     */
    public function invalidNameSpaceProvider()
    {
        $user = ':openconext:unique-user-id';

        return [
            'no namespace'              => [$user],
            'prefixed wrong namepace'   => ['urn:not-collab:person'],
            'affixed correct namespace' => [$user . EngineBlock_UserDirectory::URN_COLLAB_PERSON_NAMESPACE]
        ];
    }

    /**
     * @test
     * @group        EngineBlock
     * @group        Authentication
     */
    public function collab_person_id_can_be_retrieved()
    {
        $collabPersonIdValue = EngineBlock_UserDirectory::URN_COLLAB_PERSON_NAMESPACE . ':openconext:unique-user-id';

        $collabPersonId = new CollabPersonId($collabPersonIdValue);

        $this->assertEquals($collabPersonIdValue, $collabPersonId->getCollabPersonId());
    }

    /**
     * @test
     * @group        EngineBlock
     * @group        Authentication
     */
    public function collab_person_ids_are_only_equal_if_created_with_the_same_value()
    {
        $firstId  = EngineBlock_UserDirectory::URN_COLLAB_PERSON_NAMESPACE . ':openconext:unique-user-id';
        $secondId = EngineBlock_UserDirectory::URN_COLLAB_PERSON_NAMESPACE . ':openconext:other-user-id';

        $base = new CollabPersonId($firstId);
        $same = new CollabPersonId($firstId);
        $different = new CollabPersonId($secondId);

        $this->assertTrue($base->equals($same));
        $this->assertFalse($base->equals($different));
    }

    /**
     * @test
     * @group        EngineBlock
     * @group        Authentication
     */
    public function a_collab_person_id_can_be_cast_to_string()
    {
        $collabPersonIdValue = EngineBlock_UserDirectory::URN_COLLAB_PERSON_NAMESPACE . ':openconext:unique-user-id';

        $collabPersonId = new CollabPersonId($collabPersonIdValue);

        $this->assertInternalType('string', (string) $collabPersonId);
    }
}
