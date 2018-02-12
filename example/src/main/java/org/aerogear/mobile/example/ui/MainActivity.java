package org.aerogear.mobile.example.ui;

import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.NavigationView;
import android.support.v4.app.Fragment;
import android.support.v4.view.GravityCompat;
import android.support.v4.widget.DrawerLayout;
import android.support.v7.app.ActionBarDrawerToggle;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.MenuItem;

import org.aerogear.android.ags.auth.AuthService;
import org.aerogear.android.ags.auth.Callback;
import org.aerogear.android.ags.auth.IUserPrincipal;
import org.aerogear.android.ags.auth.impl.IActivityAuthResultHandler;
import org.aerogear.android.ags.auth.impl.IKeycloakAuthActivity;
import org.aerogear.mobile.example.R;

import butterknife.BindView;
import butterknife.ButterKnife;

public class MainActivity extends BaseActivity
    implements NavigationView.OnNavigationItemSelectedListener, IKeycloakAuthActivity {

    private AuthFragment authFragment;

    @BindView(R.id.toolbar)
    Toolbar toolbar;

    @BindView(R.id.drawer_layout)
    DrawerLayout drawer;

    @BindView(R.id.nav_view)
    NavigationView navigationView;

    private IActivityAuthResultHandler handler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ButterKnife.bind(this);

        setSupportActionBar(toolbar);

        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
            this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.addDrawerListener(toggle);
        toggle.syncState();

        navigationView.setNavigationItemSelectedListener(this);

        navigateTo(new HomeFragment());
    }

    @Override
    public void onBackPressed() {
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onNavigationItemSelected(@NonNull MenuItem item) {
        switch (item.getItemId()) {
            case R.id.nav_http:
                navigateTo(new HttpFragment());
                break;
            case R.id.nav_auth:
                authFragment = new AuthFragment();
                navigateTo(authFragment);
                break;
            default:
                navigateTo(new HomeFragment());
                break;
        }

        drawer.closeDrawer(GravityCompat.START);
        return true;
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == AuthService.LOGIN_REQUEST_CODE) {
            handler.onResult();
//            AuthService authService = (AuthService) mobileCore.getInstance(AuthService.class);
//            authService.handleAuthResponse(data, new Callback<IUserPrincipal>() {
//                @Override
//                public void onSuccess(IUserPrincipal user) {
//                    authFragment.addElement("You are logged in!");
//                    authFragment.addElement("Username", user.getName());
//                }
//
//                @Override
//                public void onError(Throwable error) {
//                    authFragment.addElement("Login failed", error.getMessage());
//                }
//            });
        }
    }

    private void navigateTo(Fragment fragment) {
        getSupportFragmentManager()
            .beginTransaction()
            .replace(R.id.content, fragment)
            .commit();
    }

    @Override
    public void setCallBack(IActivityAuthResultHandler handler) {
        this.handler = handler;
    }
}
