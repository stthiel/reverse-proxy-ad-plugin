package org.jenkinsci.plugins.reverse_proxy_auth.model;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;

import java.util.Map;

/**
 * Created by:
 * User: ssthiel
 * Mail: stthiel@users.noreply.github.com
 * Date: 20.08.14
 * Time: 10:47
 * <p/>
 * All rights reserved.
 */
@Extension
public class DomainUserCanonicalIdResolver extends User.CanonicalIdResolver {

    @Override
    public String resolveCanonicalId(String idOrFullName, Map<String, ?> context) {
        return idOrFullName;
    }

    @Override
    public int getPriority() {
        return Integer.MAX_VALUE;
    }

    @Override
    public Descriptor<User.CanonicalIdResolver> getDescriptor() {
        return DESCRIPTOR;
    }

    public static final Descriptor<User.CanonicalIdResolver> DESCRIPTOR = new Descriptor<User.CanonicalIdResolver>() {
        public String getDisplayName() {
            return "compute domain users ID as is";
        }
    };
}
