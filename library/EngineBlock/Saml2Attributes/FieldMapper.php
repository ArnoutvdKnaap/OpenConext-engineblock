<?php
 
class EngineBlock_Saml2Attributes_FieldMapper
{
    /**
     * Manually converted from LDAP schema files
     *
     * @var array
     */
    protected $_s2lMap = array(
        'urn:mace:dir:attribute-def:uid'                                => 'uid',
        'urn:mace:dir:attribute-def:cn'                                 => 'cn',
        'urn:mace:dir:attribute-def:givenName'                          => 'givenName',
        'urn:mace:dir:attribute-def:sn'                                 => 'sn',
        'urn:mace:dir:attribute-def:displayName'                        => 'displayName',
        'urn:mace:dir:attribute-def:mail'                               => 'mail',
        'urn:mace:terena.org:attribute-def:schacHomeOrganization'       => 'o',

        'urn:mace:dir:attribute-def:eduPersonAffiliation'               => 'eduPersonAffiliation',
        # Specifies a person's relationship(s) to the institution in
        # broad categories such as student, faculty, staff, alum, etc.

        'urn:mace:dir:attribute-def:eduPersonNickname'                  => 'eduPersonNickname',
        # Specifies a person's nickname, or the informal name by which
        # they are accustomed to be hailed.

        'urn:mace:dir:attribute-def:eduPersonOrgDN'                     => 'eduPersonOrgDN',
        # The distinguished name (DN) of the directory entry
        # representing the institution with which the person
        # is associated.

        'urn:mace:dir:attribute-def:eduPersonOrgUnitDN'                 => 'eduPersonOrgUnitDN',
        # The distinguished name (DN) of the directory entries representing
        # the person's Organizational Unit(s).

        'urn:mace:dir:attribute-def:eduPersonPrimaryAffiliation'        => 'eduPersonPrimaryAffiliation',
        # Specifies a person's PRIMARY relationship to the institution
        # in broad categories such as student, faculty, staff, alum, etc.

        'urn:mace:dir:attribute-def:eduPersonPrincipalName'             => 'eduPersonPrincipalName',
        # The "NetID" of the person for the purposes of inter-institutional
        # authentication.  Should be stored in the form of user@univ.edu,
        # where univ.edu is the name of the local security domain.

        'urn:mace:dir:attribute-def:eduPersonEntitlement'               => 'eduPersonEntitlement',

        'urn:mace:dir:attribute-def:eduPersonPrimaryOrgUnitDN'          => 'eduPersonPrimaryOrgUnitDN',

        'urn:mace:dir:attribute-def:eduPersonScopedAffiliation'         => 'eduPersonScopedAffiliation',
        # nlEduPerson, see also: http://www2.surfnet.nl/diensten/ldap/oid/

        'urn:mace:surffederatie.nl:attribute-def:nlEduPersonOrgUnit'    => 'nlEduPersonOrgUnit',
        # examples: "Faculteit der Letteren", "Bibliotheek", "IT Diensten"

        'urn:mace:surffederatie.nl:attribute-def:nlEduPersonStudyBranch'=> 'nlEduPersonStudyBranch',
        # example: 52734
        # See also:
        # http://www.ib-groep.nl/zakelijk/HO/CROHO/Raadplegen_of_downloaden_CROHO.asp
        
        'urn:mace:surffederatie.nl:attribute-def:nlStudielinkNummer'    => 'nlStudielinkNummer',
        'urn:mace:surffederatie.nl:attribute-def:nlEduPerson'           => 'nlEduPerson',
    );

    public function saml2AttributesToLdapAttributes($attributes)
    {
        $ldapAttributes = array();
        foreach ($attributes as $saml2Name => $values) {
            if (isset($this->_s2lMap[$saml2Name])) {
                if (count($values)>1) {
                    ebLog()->notice("Ignoring everything but first value of $saml2Name: ". var_export($values, true));
                }
                
                $ldapAttributes[$this->_s2lMap[$saml2Name]] = $values[0];
            }
        }
        return $ldapAttributes;
    }
}
