package org.aerogear.mobile.example.ui;

import android.databinding.ObservableArrayList;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;

import com.github.nitrico.lastadapter.LastAdapter;

import org.aerogear.android.ags.auth.AuthService;
import org.aerogear.mobile.example.BR;
import org.aerogear.mobile.example.R;

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
        authService.performAuthRequest(this.getContext().getApplicationContext(), Uri.parse("org.aerogear.mobile.example:/callback"), this.getActivity());
    }

    public void addElement(String key, String val) {
        addElement(key + ": " + val);
    }

    public void addElement(String val) {
        userDetails.add(val);
    }

}
