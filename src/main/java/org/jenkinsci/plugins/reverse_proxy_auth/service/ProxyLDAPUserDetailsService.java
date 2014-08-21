package org.jenkinsci.plugins.reverse_proxy_auth.service;

import hudson.model.User;
import hudson.security.UserMayOrMayNotExistException;
import hudson.tasks.Mailer;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.ldap.LdapDataAccessException;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.apache.commons.collections.map.LRUMap;
import org.jenkinsci.plugins.reverse_proxy_auth.ReverseProxySecurityRealm;
import org.jenkinsci.plugins.reverse_proxy_auth.model.FilterBasedLdapSearch;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ProxyLDAPUserDetailsService implements UserDetailsService {

    private static final Logger LOGGER = Logger.getLogger(ProxyLDAPUserDetailsService.class.getName());
    public static final String DC = "DC=";
    public static final String MEMBER_OF = "memberOf";
    public static final String OBJECT_CATEGORY = "objectCategory";
    public static final String PERSON = "Person";
    public static final String DISPLAY_NAME = "displayName";
    public static final String MAIL = "mail";

    public final FilterBasedLdapSearch ldapSearch;
    public final LdapAuthoritiesPopulator authoritiesPopulator;

    /**
     * {@link BasicAttributes} in LDAP tend to be bulky (about 20K at size), so interning them
     * to keep the size under control. When a programmatic client is not smart enough to
     * reuse a session, this helps keeping the memory consumption low.
     */
    private final LRUMap attributesCache = new LRUMap(32);

    private final static Pattern pattern = Pattern.compile("^CN=([\\w -]*),.*$");

    public ProxyLDAPUserDetailsService(ReverseProxySecurityRealm securityRealm, WebApplicationContext appContext) {
        ldapSearch = securityRealm.extractBean(FilterBasedLdapSearch.class, appContext);
        authoritiesPopulator = securityRealm.extractBean(LdapAuthoritiesPopulator.class, appContext);
    }

    @Override
    public LdapUserDetails loadUserByUsername(String userName) throws UsernameNotFoundException, DataAccessException {
        try {
            String[] strings = userName.split(";");
            LdapUserDetails ldapUser = null;
            if (strings.length == 2) {
                ldapSearch.setSearchBase(DC + strings[0]);
                ldapUser = ldapSearch.searchForUser(strings[1]);
            } else {
                ldapSearch.setSearchBase("");
                ldapUser = ldapSearch.searchForUser(strings[0]);
            }

            if (ldapUser != null) {
                LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence(ldapUser);

                // intern attributes
                Attributes v = ldapUser.getAttributes();
                if (v instanceof BasicAttributes) {// BasicAttributes.equals is what makes the interning possible
                    synchronized (attributesCache) {
                        Attributes vv = (Attributes) attributesCache.get(v);
                        if (vv == null) attributesCache.put(v, vv = v);
                        user.setAttributes(vv);
                    }
                }
                // MS=AD does populate group membership via attribute 'memberOf'
                Attribute memberOf = v.get(MEMBER_OF);
                NamingEnumeration<?> memberOfAll = memberOf.getAll();
                while (memberOfAll.hasMoreElements()) {
                    String role = String.class.cast(memberOfAll.next());
                    Matcher matcher = pattern.matcher(role);
                    if (matcher.find()) {
                        String roleName = matcher.group(1);
                        user.addAuthority(new GrantedAuthorityImpl(roleName));
                    }
                }
                ldapUser = user.createUserDetails();

                // we want to retrieve groups here as well and need to distinguish between persons here
                Attribute objectCategory = v.get(OBJECT_CATEGORY);
                Matcher matcher = pattern.matcher(objectCategory.get().toString());
                if (matcher.find() && matcher.group(1).equalsIgnoreCase(PERSON)) {
                    // if a person is found, we want to save display name and mail address as well
                    User hudsonUser = User.get(userName);
                    if (hudsonUser.getFullName() == null || hudsonUser.getFullName().isEmpty() || hudsonUser.getFullName().equalsIgnoreCase(userName)) {
                        if (v.get(DISPLAY_NAME).get() != null)
                            hudsonUser.setFullName(v.get(DISPLAY_NAME).get().toString());
                    }
                    if ((hudsonUser.getProperty(Mailer.UserProperty.class) == null) || (hudsonUser.getProperty(Mailer.UserProperty.class).getAddress() == null)) {
                        if(v.get(MAIL) != null && v.get(MAIL).get() != null)
                            hudsonUser.addProperty(new Mailer.UserProperty(v.get(MAIL).get().toString()));
                    }
                }
            }

            return ldapUser;
        } catch (LdapDataAccessException e) {
            LOGGER.log(Level.WARNING, "Failed to search LDAP for username=" + userName, e);
            throw new UserMayOrMayNotExistException(e.getMessage(), e);
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING, "Failed to get Roles for username=" + userName, e);
            throw new UserMayOrMayNotExistException(e.getMessage(), e);
        } catch (IllegalStateException e) {
            LOGGER.log(Level.WARNING, "Failed to get Roles for username=" + userName, e);
            throw new UserMayOrMayNotExistException(e.getMessage(), e);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to get Properties for username=" + userName, e);
            throw new UserMayOrMayNotExistException(e.getMessage(), e);
        }
    }
}