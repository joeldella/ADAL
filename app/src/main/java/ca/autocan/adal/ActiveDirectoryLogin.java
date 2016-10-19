package ca.autocan.adal;

import android.app.Fragment;
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.webkit.CookieManager;

import android.webkit.CookieSyncManager;
import android.widget.Toast;

import com.microsoft.aad.adal.AuthenticationCallback;
import com.microsoft.aad.adal.AuthenticationContext;
import com.microsoft.aad.adal.AuthenticationResult;
import com.microsoft.aad.adal.IWindowComponent;
import com.microsoft.aad.adal.PromptBehavior;

public class ActiveDirectoryLogin extends AppCompatActivity {

    /**
     * UTF-8 encoding
     */
    static final String AUTHORITY_URL = "https://login.windows.net/appdevautocan.onmicrosoft.com";
    static final String CLIENT_ID = "a9df0e66-7ce8-40e7-963f-44ab54d9fc52";
    static final String REDIRECT_URL = "https://guestsurveycore.azurewebsites.net";
    static final String RESOURCE_ID = "02b674e1-1cf5-487b-b479-82fad3ec29d2";

    private AuthenticationContext mAuthContext;

    private AuthenticationResult mResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.active_directory_login);
        try {
            mAuthContext = new AuthenticationContext(getApplicationContext(),
                    AUTHORITY_URL, false);
        } catch (Exception e) {
            Toast.makeText(getApplicationContext(), "Encryption failed",
                    Toast.LENGTH_SHORT).show();
        }
    }

    private IWindowComponent wrapFragment(final Fragment fragment) {
        return new IWindowComponent() {
            Fragment refFragment = fragment;

            @Override
            public void startActivityForResult(Intent intent, int requestCode) {
                refFragment.startActivityForResult(intent, requestCode);
            }
        };
    }

    public void signIn (final View v) {
        if (mResult != null) {
            // logout
            CookieManager cookieManager = CookieManager.getInstance();
            cookieManager.removeAllCookie();
            CookieSyncManager.getInstance().sync();
            mAuthContext.getCache().removeAll();
        } else {
            // login
            mAuthContext.acquireToken(ActiveDirectoryLogin.this, RESOURCE_ID,
                    CLIENT_ID, REDIRECT_URL, "", PromptBehavior.Auto, "",
                    getCallback());
        }
    }

    private static final String TAG = "DEBUG";
    private void showInfo(String msg) {
        Log.d(TAG, msg);
    }

    private AuthenticationCallback<AuthenticationResult> getCallback() {
        return new AuthenticationCallback<AuthenticationResult>() {

            @Override
            public void onError(Exception exc) {
                showInfo("getToken Error:" + exc.getMessage());
            }

            @Override
            public void onSuccess(AuthenticationResult result) {
                mResult = result;
                showInfo("Token info:" + result.getAccessToken());
                showInfo("IDToken info:" + result.getIdToken());
                showInfo("Token is returned");

                if (mResult.getUserInfo() != null) {
                    showInfo("User info userid:" + result.getUserInfo().getUserId()
                            + " displayableId:" + result.getUserInfo().getDisplayableId());
                    //textView.setText(result.getUserInfo().getDisplayableId());
                }
            }
        };
    }
}