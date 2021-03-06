package org.aerogear.mobile.example.ui;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;

import org.aerogear.mobile.core.MobileCore;
import org.aerogear.mobile.example.ExampleApplication;

public abstract class BaseActivity extends AppCompatActivity {

    MobileCore mobileCore;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mobileCore = ((ExampleApplication) getApplication()).getMobileCore();
    }
}
