package org.aerogear.android.ags.auth.credentials;

import android.content.Context;
import android.net.Uri;

import org.aerogear.android.ags.auth.impl.IKeycloakAuthActivity;

public class KeyCloakWebCredentials implements ICredential {
    private final Context ctx;
    private final Uri redirectUri;
    private final IKeycloakAuthActivity fromActivity;

    public KeyCloakWebCredentials(final Context ctx, final Uri redirectUri, final IKeycloakAuthActivity fromActivity) {
        this.ctx = ctx;
        this.redirectUri = redirectUri;
        this.fromActivity = fromActivity;
    }

    public IKeycloakAuthActivity getFromActivity() {
        return fromActivity;
    }

    public Context getCtx() {
        return ctx;
    }

    public Uri getRedirectUri() {
        return redirectUri;
    }
}
