package com.example.android.fingerprintdialog;

import android.app.Application;

/**
 * Created by christof on 18.04.16.
 */
public class MyApplication extends Application{

    // Singleton instance
    private static MyApplication mInstance = null;

    @Override
    public void onCreate() {
        super.onCreate();
        // Setup singleton instance
        mInstance = this;
    }

    // Getter to access Singleton instance
    public static MyApplication getInstance() {
        return mInstance ;
    }
}
