package org.aerogear.android.ags.auth;

import android.content.Context;
import android.content.Intent;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationService;
import org.aerogear.android.ags.auth.credentials.KeyCloakWebCredentials;
import org.aerogear.android.ags.auth.credentials.OIDCCredentials;
import org.aerogear.android.ags.auth.impl.OIDCAuthCodeImpl;
import org.aerogear.android.ags.auth.impl.OIDCTokenAuthenticatorImpl;
import org.aerogear.mobile.core.MobileCore;
import org.aerogear.mobile.core.ServiceModule;
import org.aerogear.mobile.core.configuration.ServiceConfiguration;
import java.security.Principal;
import java.util.concurrent.Future;
/**
 * Entry point for authenticating users.
 */
public class AuthService implements ServiceModule {

    private ServiceConfiguration serviceConfiguration;
    private AuthorizationService authService;
    private AuthState authState;

    private OIDCAuthCodeImpl oidcAuthCodeImpl;
    private OIDCTokenAuthenticatorImpl oidcTokenAuthenticator;

    public static final int LOGIN_REQUEST_CODE = 1;

    /**
     * Instantiates a new AuthService object
     */
    public AuthService() {}

    /**
     * Log in the user with the given credential. Flow to be used to authenticate the user is automatically
     * selected by analysing the received credentials. If the credentials are null,
     * the browser will be open asking for authentication
     *
     * The login will be asynchronous.
     *
     * @param credentials the credential
     * @return a user principal
     */
    // TODO: We don't use login, we wrap AppAuth more closely and provide similar methods to it
    // So the flow is
    // AuthService.performAuthRequest (Provide an activity)
    // AuthService.handleAuthResponse (Do this back in the activity)
    public void login(final KeyCloakWebCredentials credentials) throws AuthenticationException {
        oidcAuthCodeImpl.authenticate(credentials);
    }

    public void login(final OIDCCredentials credentials, Callback<Principal> callback) throws AuthenticationException {
        oidcTokenAuthenticator.authenticate(credentials, callback);
    }

    public void handleAuthResult(Intent intent, Callback<Principal> callback) {
        oidcAuthCodeImpl.handleAuthResult(intent, callback);
    }

    /**
     * Log out the given principal.
     * The logout will be asynchronous.
     *
     * @param principal principal to be logged out
     */
    public Future<Void> logout(Principal principal) {
//        if (principal instanceof AbstractPrincipal) {
//            return authenticatorChain.logout(principal);
//        }

        throw new IllegalArgumentException("Unknown principal type " + principal.getClass().getName());
    }

    @Override
    public String type() {
        return "keycloak";
    }

    @Override
    public void configure(final MobileCore core, final ServiceConfiguration serviceConfiguration) {
        this.serviceConfiguration = serviceConfiguration;
        this.oidcAuthCodeImpl = new OIDCAuthCodeImpl(serviceConfiguration);
        this.oidcTokenAuthenticator = new OIDCTokenAuthenticatorImpl(serviceConfiguration);
    }

    /**
     * Initialize the module. This should be called before any other method when using the module.
     * @param context
     */
    public void init(final Context context) {
        AuthStateManager.getInstance(context);
    }

    @Override
    public void destroy() {

    }
}

