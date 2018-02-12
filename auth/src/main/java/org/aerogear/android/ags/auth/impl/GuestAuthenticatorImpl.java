package org.aerogear.android.ags.auth.impl;

import org.aerogear.android.ags.auth.AbstractAuthenticator;
import org.aerogear.android.ags.auth.UserRole;
import org.aerogear.android.ags.auth.credentials.ICredential;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Future;

import java8.util.concurrent.CompletableFuture;

/**
 * Simple authenticator to return 'guest' users.
 * No authentication is performed at all.
 */
public class GuestAuthenticatorImpl extends AbstractAuthenticator {

    /**
     * The 'guest' username to return.
     */
    private final String guestUser;

    /**
     * Roles to be assigned to the guest user
     */
    private final Set<UserRole> roles;

    /**
     * Builds a new guest authenticator object
     * @param guestUser the user to be returned after the 'authentication'
     * @param roles the roles to be assigned to the user
     */
    public GuestAuthenticatorImpl(final String guestUser, final Set<UserRole> roles) {
        super(null);
        this.guestUser = guestUser;
        if (roles == null) {
            this.roles = new HashSet<>();
        } else {
            this.roles = Collections.synchronizedSet(new HashSet<>(roles));
        }
    }

    /**
     * Simply returns a user with username {@link #guestUser}
     * @param credential user credential
     * @return a user with username {@link #guestUser}
     */
    public Future<Principal> authenticate(final ICredential credential) {
        try {
            CompletableFuture res = new CompletableFuture();

            res.complete(UserPrincipalImpl
                .newUser()
                .withAuthenticator(this)
                .withUsername(guestUser)
                .withRoles(roles)
                .build());
            return res;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void logout(Principal principal) {
        return;
    }
}
