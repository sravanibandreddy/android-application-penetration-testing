package com.android.insecurebankv2;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;

public class LoginActivity extends Activity {

    private static final String TAG = "INSECURE_BANK";
    // VULNERABILITY M3: Insecure plain HTTP endpoint
    private static final String AUTH_ENDPOINT = "http://insecurebank.local:8080/login";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
    }

    /**
     * VULNERABILITY M4: Hardcoded credentials & client-side authentication bypass
     */
    public boolean authenticateUser(String username, String password) {
        // VULNERABILITY M2: Insecure Logging of sensitive credentials
        Log.d(TAG, "Attempting authentication for user: " + username + " with password: " + password);

        // Flawed client-side check
        if (username.equals("admin") && password.equals("admin")) {
            saveCredentialsInsecurely(username, password);
            return true;
        }
        return false;
    }

    /**
     * VULNERABILITY M2: Storing credentials in plaintext SharedPreferences
     */
    private void saveCredentialsInsecurely(String username, String password) {
        SharedPreferences pref = getSharedPreferences("credentials", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("username", username);
        editor.putString("password", password); // Stored in cleartext in shared_prefs/credentials.xml
        editor.apply();
    }
}
