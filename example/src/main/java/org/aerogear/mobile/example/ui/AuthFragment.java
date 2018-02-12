package org.aerogear.mobile.example.ui;

import android.databinding.ObservableArrayList;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;

import com.github.nitrico.lastadapter.LastAdapter;

import org.aerogear.android.ags.auth.AuthService;
import org.aerogear.android.ags.auth.IUserPrincipal;
import org.aerogear.android.ags.auth.credentials.KeyCloakWebCredentials;
import org.aerogear.android.ags.auth.impl.IKeycloakAuthActivity;
import org.aerogear.mobile.example.BR;
import org.aerogear.mobile.example.R;

import java.security.Principal;
import java.util.concurrent.Future;

import butterknife.BindView;

public class AuthFragment extends BaseFragment {

    @BindView(R.id.authList)
    RecyclerView authDetailList;

    private ObservableArrayList<String> userDetails = new ObservableArrayList<>();

    @Override
    int getLayoutResId() {
        return R.layout.fragment_auth;
    }

    @Override
    public void onActivityCreated(@Nullable Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        authDetailList.setLayoutManager(new LinearLayoutManager(getContext()));

        new LastAdapter(userDetails, BR.detail)
            .map(String.class, R.layout.item_auth)
            .into(authDetailList);

        AuthService authService = (AuthService) activity.mobileCore.getInstance(AuthService.class);
        authService.init(this.getContext().getApplicationContext());

        Future<Principal> principal;
        principal = authService.login(new KeyCloakWebCredentials(this.getContext().getApplicationContext(), Uri.parse("org.aerogear.mobile.example:/callback"), (IKeycloakAuthActivity) this.getActivity()));

        try {
            IUserPrincipal userPrincipal = (IUserPrincipal) principal.get();
            this.addElement("You are logged in!");
            this.addElement("Username", userPrincipal.getName());
        } catch (Exception error) {
            this.addElement("Login failed", error.getMessage());
        }

        //@Override
//                public void onSuccess(IUserPrincipal user) {
//                    authFragment.addElement("You are logged in!");
//                    authFragment.addElement("Username", user.getName());
//                }
//
//                @Override
//                public void onError(Throwable error) {
//                    authFragment.addElement("Login failed", error.getMessage());
//                }


        //authService.performAuthRequest(this.getContext().getApplicationContext(), Uri.parse("org.aerogear.mobile.example:/callback"), this.getActivity());

    }

    public void addElement(String key, String val) {
        addElement(key + ": " + val);
    }

    public void addElement(String val) {
        userDetails.add(val);
    }

}
