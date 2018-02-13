package org.aerogear.android.ags.auth;

import org.aerogear.android.ags.auth.credentials.ICredential;
import org.aerogear.mobile.core.configuration.ServiceConfiguration;

import java.security.Principal;
import java.util.concurrent.Future;

/**
 * Base class for all authenticators
 */
public class AbstractAuthenticator {

    /**
     * Authentication service configuration.
     */
    private final ServiceConfiguration serviceConfig;


    public AbstractAuthenticator(final ServiceConfiguration serviceConfig) {
        this.serviceConfig = serviceConfig;
    }

    /**
     * This method must be overridden with the custom authentication for the given credential.
     *
     * @param credential user credential
     */
    public void authenticate(final ICredential credential, final Callback<Principal> callback) throws AuthenticationException {
        throw new IllegalStateException("Not implemented");
    }

    /**
     * Logout the given principal
     * @param principal principal to be log out
     */
    public void logout(final Principal principal) {
        throw new IllegalStateException("Not implemented");
    }

    /**
     * Returns the authentication service configuration
     * @return the authentication service configuration
     */
    public ServiceConfiguration getServiceConfig() { return this.serviceConfig; }
}
