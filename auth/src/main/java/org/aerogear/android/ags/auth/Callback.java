package org.aerogear.android.ags.auth;

public interface Callback<T extends Object> {
    public void onSuccess(T models);
    public void onError(Throwable error);
}
