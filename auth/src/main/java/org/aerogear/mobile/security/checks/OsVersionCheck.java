package org.aerogear.mobile.security.checks;

import android.content.Context;
import android.os.Build;

import org.aerogear.mobile.security.SecurityCheck;
import org.aerogear.mobile.security.SecurityCheckResult;
import org.aerogear.mobile.security.impl.SecurityCheckResultImpl;

public class OsVersionCheck implements SecurityCheck {
    private static final String NAME = "checkIfLatestAndroid";

    @Override
    public SecurityCheckResult test(Context context) {
        int latestOsApiLevel = Build.VERSION_CODES.M;

        if (Build.VERSION.SDK_INT < latestOsApiLevel) {
            return new SecurityCheckResultImpl(NAME, false);
        } else {
            return new SecurityCheckResultImpl(NAME, true);
        }
    }
}
