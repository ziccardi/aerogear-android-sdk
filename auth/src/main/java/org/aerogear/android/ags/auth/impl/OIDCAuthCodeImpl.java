package org.aerogear.android.ags.auth.impl;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.Nullable;
import android.util.Base64;

import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.TokenResponse;
import net.openid.appauth.browser.BrowserBlacklist;
import net.openid.appauth.browser.VersionedBrowserMatcher;

import org.aerogear.android.ags.auth.AuthStateManager;
import org.aerogear.android.ags.auth.AuthenticationException;
import org.aerogear.android.ags.auth.Callback;
import org.aerogear.android.ags.auth.IUserPrincipal;
import org.aerogear.android.ags.auth.RoleType;
import org.aerogear.android.ags.auth.UserRole;
import org.aerogear.android.ags.auth.configuration.AuthenticationConfiguration;
import org.aerogear.android.ags.auth.credentials.ICredential;
import org.aerogear.android.ags.auth.credentials.KeyCloakWebCredentials;
import org.aerogear.android.ags.auth.credentials.OIDCCredentials;
import org.aerogear.android.ags.auth.debug.ConnectionBuilderForTesting;
import org.aerogear.mobile.core.configuration.ServiceConfiguration;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

import java8.util.concurrent.CompletableFuture;


/**
 * Authenticates the user by using OpenID Connect.
 */
public class OIDCAuthCodeImpl extends OIDCTokenAuthenticatorImpl implements IActivityAuthResultHandler {

    private static final String USERNAME = "preferred_username";
    private static final String EMAIL = "email";
    private static final String REALM = "realm_access";
    private static final String CLIENT = "resource_access";
    private static final String ROLES = "roles";
    private static final String RESOURCE = "resource";
    private static final String COMMA = ",";

    private JSONObject userIdentity = new JSONObject();

    private static final int LOGIN_REQUEST_CODE = 1;

    private AuthState authState;
    private Intent authIntent;

    private CompletableFuture<Principal> completableFuture;

    private Semaphore semaphore = new Semaphore(1);

    private CompletableFuture<Principal> principalFuture;

    private AuthorizationService authService;

    /**
     * Creates a new OIDCAuthCodeImpl object
     *
     * @param serviceConfig {@link ServiceConfiguration}
     */
    public OIDCAuthCodeImpl(final ServiceConfiguration serviceConfig) {
        super(serviceConfig);
    }

    /**
     * Builds a new OIDCUserPrincipalImpl object after the user's credential has been authenticated
     *
     * @param credential the OIDC credential for the user
     * @return a new OIDCUserPrincipalImpl object with the user's identity {@link #userIdentity} that was decoded from the user's credential
     * @throws AuthenticationException
     * @see OIDCTokenAuthenticatorImpl#authenticate(ICredential)
     */
    @Override
    public Future<Principal> authenticate(final ICredential credential) throws AuthenticationException {
        if (!(credential instanceof KeyCloakWebCredentials)) {
            return null;
        }

        KeyCloakWebCredentials keyCloakWebCredentials = (KeyCloakWebCredentials) (credential);

        return performAuthRequestFuture(keyCloakWebCredentials.getCtx(), keyCloakWebCredentials.getRedirectUri(), keyCloakWebCredentials.getFromActivity());
    }

    // Authentication code
    private CompletableFuture<Principal>  performAuthRequestFuture(final Context ctx, final Uri redirectUri, final IKeycloakAuthActivity fromActivity) { // FROM Activity == MainActivity

        fromActivity.setCallBack(this);

        AuthenticationConfiguration authConfig = new AuthenticationConfiguration(getServiceConfig());
        AuthorizationServiceConfiguration authServiceConfig = new AuthorizationServiceConfiguration(
            authConfig.getAuthenticationEndpoint(),
            authConfig.getTokenEndpoint()
        );

        this.authState = new AuthState(authServiceConfig);
        OIDCCredentials credentials = new OIDCCredentials(authState.jsonSerializeString(), null);
        AuthStateManager.getInstance().save(credentials);

        AppAuthConfiguration appAuthConfig = new AppAuthConfiguration.Builder()
            .setBrowserMatcher(new BrowserBlacklist(
                VersionedBrowserMatcher.CHROME_CUSTOM_TAB))
            .setConnectionBuilder(new ConnectionBuilderForTesting())
            .build();

        this.authService = new AuthorizationService(ctx, appAuthConfig);
        //this.authService = authService;
        AuthorizationRequest authRequest = new AuthorizationRequest.Builder(
            authServiceConfig,
            authConfig.getClientId(),
            ResponseTypeValues.CODE,
            redirectUri).build();

        this.authIntent = authService.getAuthorizationRequestIntent(authRequest);
        ((Activity)fromActivity).startActivityForResult(this.authIntent, LOGIN_REQUEST_CODE);

        return this.principalFuture = new CompletableFuture<>();
    }

    @Override
    public void onResult() {
        AuthorizationResponse response = AuthorizationResponse.fromIntent(this.authIntent);
        AuthorizationException error = AuthorizationException.fromIntent(this.authIntent);

        authState.update(response, error);
        AuthStateManager.getInstance().save(new OIDCCredentials(authState.jsonSerializeString(), null));

        if (response != null) {
            exchangeTokens(response);
        } else {
            this.completableFuture.completeExceptionally(error);
            //callback.onError(error);
        }
    }

    private void exchangeTokens(final AuthorizationResponse response) {
        authService.performTokenRequest(response.createTokenExchangeRequest(), new AuthorizationService.TokenResponseCallback() {
            @Override
            public void onTokenRequestCompleted(@Nullable TokenResponse tokenResponse, @Nullable AuthorizationException exception) {
                if (tokenResponse != null) {
                    authState.update(tokenResponse, exception);
                    AuthStateManager.getInstance().save(new OIDCCredentials(authState.jsonSerializeString(), null));

                    OIDCCredentials credentials = AuthStateManager.getInstance().load();
                    try {
                        UserPrincipalImpl user = UserPrincipalImpl.newUser()
                            .withCredentials(credentials)
                            .build();
                        OIDCAuthCodeImpl.this.completableFuture.complete(user);
                    } catch(Exception e) {
                        OIDCAuthCodeImpl.this.completableFuture.completeExceptionally(e);
                    }
                } else {
                    OIDCAuthCodeImpl.this.completableFuture.completeExceptionally(new RuntimeException(exception));
                }
            }
        });
    }
    //////////////////////////////////////////////////////


    /**
     * Parses the user's username from the user identity {@link #userIdentity}
     *
     * @return user's username
     * @throws JSONException
     */
    private String parseUsername() throws JSONException {
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
     * Parses the user's email address from the user identity {@link #userIdentity}
     *
     * @return user's email address
     * @throws JSONException
     */
    private String parseEmail() throws JSONException {
        String emailAddress = "Unknown Email";
        if (userIdentity != null) {
            // get the users email
            if (userIdentity.has(EMAIL) && userIdentity.getString(EMAIL).length() > 0) {
                emailAddress = userIdentity.getString(EMAIL);
            }
        }
        return emailAddress;
    }

    /**
     * Parses the user's roles from the user identity {@link #userIdentity}
     *
     * @return user's roles
     * @throws JSONException
     */
    private Set<UserRole> parseRoles() throws JSONException {
        Set<UserRole> roles = new HashSet<>();
        if (userIdentity != null) {
            Set<UserRole> realmRoles = parseRealmRoles();
            if (realmRoles != null) {
                roles.addAll(realmRoles);
            }
            Set<UserRole> clientRoles = parseClientRoles();
            if (clientRoles != null) {
                roles.addAll(clientRoles);
            }
        }
        return roles;
    }

    /**
     * Parses the user's realm roles from the user identity {@link #userIdentity}
     *
     * @return user's realm roles
     * @throws JSONException
     */
    private Set<UserRole> parseRealmRoles() throws JSONException {
        Set<UserRole> realmRoles = new HashSet<>();
        if (userIdentity.has(REALM) && userIdentity.getJSONObject(REALM).has(ROLES)) {
            String tokenRealmRolesJSON = userIdentity.getJSONObject(REALM).getString(ROLES);

            String realmRolesString = tokenRealmRolesJSON.substring(1, tokenRealmRolesJSON.length() - 1).replace("\"", "");
            String roles[] = realmRolesString.split(COMMA);

            for (String roleName : roles) {
                UserRole realmRole = new UserRole(roleName, RoleType.REALM, null);
                realmRoles.add(realmRole);
            }
        }
        return realmRoles;
    }

    /**
     * Parses the user's initial client roles from the user identity {@link #userIdentity}
     *
     * @return user's client roles
     * @throws JSONException
     */
    private Set<UserRole> parseClientRoles() throws JSONException {
        Set<UserRole> clientRoles = new HashSet<>();

        ServiceConfiguration serviceConfig = this.getServiceConfig();

        if (serviceConfig.getProperty(RESOURCE) != null) {
            String initialClientID = serviceConfig.getProperty(RESOURCE);  //immediate client role

            if (userIdentity.has(CLIENT) && userIdentity.getJSONObject(CLIENT).has(initialClientID)
                    && userIdentity.getJSONObject(CLIENT).getJSONObject(initialClientID).has(ROLES)) {
                String tokenClientRolesJSON = userIdentity.getJSONObject(CLIENT).getJSONObject(initialClientID).getString(ROLES);

                String clientRolesString = tokenClientRolesJSON.substring(1, tokenClientRolesJSON.length() - 1).replace("\"", "");
                String roles[] = clientRolesString.split(COMMA);

                for (String roleName : roles) {
                    UserRole clientRole = new UserRole(roleName, RoleType.CLIENT, initialClientID);
                    clientRoles.add(clientRole);
                }
            }
        }
        return clientRoles;
    }

    /**
     * Gets the user's identity by decoding the user's access token {@link OIDCCredentials#getAccessToken()}
     *
     * @param credential
     * @return user's identity
     * @throws JSONException
     * @throws AuthenticationException
     */
    private JSONObject getIdentityInformation(final ICredential credential) throws JSONException, AuthenticationException {
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
}
