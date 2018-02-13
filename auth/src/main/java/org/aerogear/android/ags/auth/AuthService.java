package org.aerogear.android.ags.auth;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.Nullable;

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

import org.aerogear.android.ags.auth.configuration.AuthenticationConfiguration;
import org.aerogear.android.ags.auth.credentials.ICredential;
import org.aerogear.android.ags.auth.credentials.OIDCCredentials;
import org.aerogear.android.ags.auth.debug.ConnectionBuilderForTesting;
import org.aerogear.android.ags.auth.impl.OIDCAuthCodeImpl;
import org.aerogear.android.ags.auth.impl.OIDCTokenAuthenticatorImpl;
import org.aerogear.android.ags.auth.impl.UserPrincipalImpl;
import org.aerogear.mobile.core.MobileCore;
import org.aerogear.mobile.core.ServiceModule;
import org.aerogear.mobile.core.configuration.ServiceConfiguration;
import java.security.Principal;
import java.util.concurrent.Future;

/**
 * Entry point for authenticating users.
 */
public class AuthService implements ServiceModule {

    private AuthenticationChain authenticatorChain;
    private ServiceConfiguration serviceConfiguration;
    private AuthorizationService authService;
    private AuthState authState;

    public static final int LOGIN_REQUEST_CODE = 1;

    /**
     * Instantiates a new AuthService object
     */
    public AuthService() {}

    private void configureDefaultAuthenticationChain(final AuthenticationChain authenticationChain) {

    }

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
    public Future<Principal> login(final ICredential credentials) {
        return authenticatorChain.authenticate(credentials);
    }

    public void login(final Context ctx, Uri redirectUri, final Activity fromActivity) {
        AuthenticationConfiguration authConfig = new AuthenticationConfiguration(serviceConfiguration);
        AuthorizationServiceConfiguration authServiceConfig = new AuthorizationServiceConfiguration(
            authConfig.getAuthenticationEndpoint(),
            authConfig.getTokenEndpoint()
        );

        authState = new AuthState(authServiceConfig);
        OIDCCredentials credentials = new OIDCCredentials(authState.jsonSerializeString(), null);
        AuthStateManager.getInstance().save(credentials);

        AppAuthConfiguration appAuthConfig = new AppAuthConfiguration.Builder()
            .setBrowserMatcher(new BrowserBlacklist(
                VersionedBrowserMatcher.CHROME_CUSTOM_TAB))
            .setConnectionBuilder(new ConnectionBuilderForTesting())
            .build();

        AuthorizationService authService = new AuthorizationService(ctx, appAuthConfig);
        this.authService = authService;
        AuthorizationRequest authRequest = new AuthorizationRequest.Builder(
            authServiceConfig,
            authConfig.getClientId(),
            ResponseTypeValues.CODE,
            redirectUri).build();

        Intent intent = authService.getAuthorizationRequestIntent(authRequest);
        fromActivity.startActivityForResult(intent, LOGIN_REQUEST_CODE);
    }

    public void handleAuthResponse(Intent intent, Callback<IUserPrincipal> callback) {
        AuthorizationResponse response = AuthorizationResponse.fromIntent(intent);
        AuthorizationException error = AuthorizationException.fromIntent(intent);

        authState.update(response, error);
        AuthStateManager.getInstance().save(new OIDCCredentials(authState.jsonSerializeString(), null));

        if (response != null) {
            exchangeTokens(response, callback);
        } else {
            callback.onError(error);
        }
    }

    private void exchangeTokens(AuthorizationResponse response, Callback<IUserPrincipal> callback) {
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
                        callback.onSuccess(user);
                    } catch(Exception e) {
                        callback.onError(e);
                    }
                } else {
                    callback.onError(new RuntimeException(exception));
                }
            }
        });
    }

    /**
     * Log out the given principal.
     * The logout will be asynchronous.
     *
     * @param principal principal to be logged out
     */
    public Future<Void> logout(Principal principal) {
        if (principal instanceof AbstractPrincipal) {
            return authenticatorChain.logout(principal);
        }

        throw new IllegalArgumentException("Unknown principal type " + principal.getClass().getName());
    }

    public void setAuthenticatorChain(AuthenticationChain newChain) {
        this.authenticatorChain = newChain;
    }

    @Override
    public String type() {
        return "keycloak";
    }

    @Override
    public void configure(final MobileCore core, final ServiceConfiguration serviceConfiguration) {
        this.serviceConfiguration = serviceConfiguration;
        this.authenticatorChain = AuthenticationChain
            .newChain()
            .with(new OIDCTokenAuthenticatorImpl(serviceConfiguration))
            .with(new OIDCAuthCodeImpl(serviceConfiguration))
            .build();
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

