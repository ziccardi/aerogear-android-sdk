package org.aerogear.android.ags.auth.impl;

import android.util.Base64;

import org.aerogear.android.ags.auth.AbstractAuthenticator;
import org.aerogear.android.ags.auth.AbstractPrincipal;
import org.aerogear.android.ags.auth.RoleType;
import org.aerogear.android.ags.auth.UserRole;
import org.aerogear.android.ags.auth.credentials.ICredential;
import org.aerogear.android.ags.auth.credentials.OIDCCredentials;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * This class represent an authenticated user
 */
public class UserPrincipalImpl extends AbstractPrincipal {

    private static final String USERNAME = "preferred_username";
    private static final String EMAIL = "email";

    /**
     * The username of the principal.
     */
    private final String username;

    /**
     * The email associated with this user
     */
    private final String email;

    /**
     * Roles associated with this principal.
     */
    private final Set<UserRole> roles;

    /**
     * User credentials. It can be null.
     */
    private final ICredential credentials;

    /**
     * Builds a new UserPrincipalImpl object
     *
     * @param username the username of the authenticated user
     * @param email the email of the authenticated user
     * @param roles roles assigned to the user
     * @param authenticator the authenticator that authenticated this user
     */
    protected UserPrincipalImpl(final String username,
                              final ICredential credentials,
                              final String email,
                              final Set<UserRole> roles,
                              final AbstractAuthenticator authenticator) {
        super(authenticator);
        this.username = username;
        this.email = email;
        this.roles = Collections.synchronizedSet(new HashSet<>(roles));
        this.credentials = credentials;
    }

    /**
     * Builds and return a UserPrincipalImpl object
     */
    public static class Builder {
        protected String username;
        protected String email;
        protected HashSet<UserRole> roles = new HashSet<>();
        protected AbstractAuthenticator authenticator;
        protected ICredential credentials;

        public Builder() {
        }

        public Builder withUsername(final String username) {
            this.username = username;
            return this;
        }

        public Builder withCredentials(final ICredential credentials) {
            this.credentials = credentials;
            return this;
        }

        public Builder withEmail(final String email) {
            this.email = email;
            return this;
        }

        Builder withRoles(final Set<UserRole> roles) {
            if (roles != null) {
                this.roles.addAll(roles);
            }
            return this;
        }

        public Builder withAuthenticator(AbstractAuthenticator authenticator) {
            this.authenticator = authenticator;
            return this;
        }

        public UserPrincipalImpl build() throws JSONException, AuthenticationException {
            JSONObject userInformation = UserPrincipalImpl.getIdentityInformation(this.credentials);
            String username = UserPrincipalImpl.parseUsername(userInformation);
            String email = UserPrincipalImpl.parseEmail(userInformation);
            return new UserPrincipalImpl(
                username,
                this.credentials,
                email,
                this.roles,
                this.authenticator);
        }
    }

    /**
     * Checks if the user has the specified Client role.
     * @param role role to be checked
     * @param clientId clientID related to role
     * @return <code>true</code> or <code>false</code>
     */
    @Override
    public boolean hasClientRole(final String role, final String clientId) {
        return roles.contains(new UserRole(role, RoleType.CLIENT, clientId));
    }

    /**
     * Checks if the user has the specified Realm role.
     * @param role role to be checked
     * @return <code>true</code> or <code>false</code>
     */
    @Override
    public boolean hasRealmRole(final String role){
        return roles.contains(new UserRole(role, RoleType.REALM, null));
    }

    @Override
    public String getName() {
        return username;
    }

    /**
     * Get's user roles
     *
     * @return user's roles
     */
    @Override
    public Set<UserRole> getRoles() {
       return roles;
    }

    @Override
    public ICredential getCredentials() {
        return credentials;
    }

    public static Builder newUser() {
        return new Builder();
    }

    // TODO: All of this is provided in a different PR and can be removed.
    /**
     * Parses the user's username from the user identity
     *
     * @return user's username
     * @throws JSONException
     */
    private static String parseUsername(JSONObject userIdentity) throws JSONException {
        String username = "Unknown Username";
        if (userIdentity != null) {
            // get the users username
            if (userIdentity.has(USERNAME) && userIdentity.getString(USERNAME).length() > 0) {
                username = userIdentity.getString(USERNAME);
            }
        }
        return username;
    }

    /**
     * Parses the user's email address from the user identity
     *
     * @return user's email address
     * @throws JSONException
     */
    private static String parseEmail(JSONObject userIdentity) throws JSONException {
        String emailAddress = "Unknown Email";
        if (userIdentity != null) {
            // get the users email
            if (userIdentity.has(EMAIL) && userIdentity.getString(EMAIL).length() > 0) {
                emailAddress = userIdentity.getString(EMAIL);
            }
        }
        return emailAddress;
    }

    private static JSONObject getIdentityInformation(final ICredential credential) throws JSONException, AuthenticationException {
        String accessToken = ((OIDCCredentials) credential).getAccessToken();
        JSONObject decodedIdentityData = new JSONObject();

        try {
            // Decode the Access Token to Extract the Identity Information
            String[] splitToken = accessToken.split("\\.");
            byte[] decodedBytes = Base64.decode(splitToken[1], Base64.URL_SAFE);
            String decoded = new String(decodedBytes, "UTF-8");
            try {
                decodedIdentityData = new JSONObject(decoded);
            } catch (JSONException e) {
                throw new AuthenticationException(e.getMessage(), e.getCause());
            }

        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationException(e.getMessage(), e.getCause());
        }
        return decodedIdentityData;
    }

    @Override
    public String toString() {
        String roleNames = "";
        Iterator<UserRole> i = roles.iterator();
        if (i.hasNext()) {
            //first element
            roleNames.concat("[").concat(i.next().getName());
            while(i.hasNext()) {
                roleNames.concat(", ").concat(i.next().getName());
            }
        }
        roleNames.concat("]");

        return "UserPrincipalImpl{" +
                "username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", roles=" + roleNames +
                '}';
    }
}
