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
    public static final String UTF8_ENCODING = "UTF-8";

    public static final String HEADER_AUTHORIZATION = "Authorization";

    public static final String HEADER_AUTHORIZATION_VALUE_PREFIX = "Bearer ";

    // AAD PARAMETERS
    // https://login.windows.net/tenantInfo
    static final String AUTHORITY_URL = "https://login.windows.net/appdevautocan";

    // Clientid is given from AAD page when you register your Android app
    static final String CLIENT_ID = "b8ae227e-d178-4ce4-9c88-0b12f4916cb2";

    // RedirectUri
    static final String REDIRECT_URL = "http://local";

    // URI for the resource. You need to setup this resource at AAD
    static final String RESOURCE_ID = "311a71cc-e848-46a1-bdf8-97ff7156d8e6";

    // Endpoint we are targeting for the deployed WebAPI service
    static final String SERVICE_URL = "https://your.serive.url.here";

    private AuthenticationContext mAuthContext;


    private AuthenticationResult mResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.active_directory_login);


        try {

            // init authentication Context
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
