package org.jenkinsci.plugins.reverse_proxy_auth.service;

import static hudson.Util.fixNull;
import hudson.security.SecurityRealm;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;

/**
 * {@link LdapAuthoritiesPopulator} that adds the automatic 'authenticated' role.
 */
public class ProxyLDAPAuthoritiesPopulator extends DefaultLdapAuthoritiesPopulator {

	// Make these available (private in parent class and no get methods!)
	private String rolePrefix = "ROLE_";
	private boolean convertToUpperCase = true;

	public ProxyLDAPAuthoritiesPopulator(InitialDirContextFactory initialDirContextFactory, String groupSearchBase) {
		super(initialDirContextFactory, fixNull(groupSearchBase));

		super.setRolePrefix("");
		super.setConvertToUpperCase(false);
	}

	@Override
	@SuppressWarnings("rawtypes")
	protected Set getAdditionalRoles(LdapUserDetails ldapUser) {
		return Collections.singleton(SecurityRealm.AUTHENTICATED_AUTHORITY);
	}

	@Override
	public void setRolePrefix(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}

	@Override
	public void setConvertToUpperCase(boolean convertToUpperCase) {
		this.convertToUpperCase = convertToUpperCase;
	}

	/**
     * Lookup the userDn retrieved from Global catalog inside the real domain and collect roles
     * from attribute 'memberOf'
	 */
	@Override
	public Set getGroupMembershipRoles(String userDn, String username) {

        Set<GrantedAuthority> names = new HashSet<GrantedAuthority>();
        return names;
	}
}