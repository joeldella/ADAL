package ca.autocan.adal;

import android.app.Activity;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Handler;
import android.util.Log;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;

import com.microsoft.azure.storage.*;
import com.microsoft.azure.storage.blob.*;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import com.microsoft.windowsazure.mobileservices.MobileServiceClient;
import com.microsoft.windowsazure.mobileservices.MobileServiceException;
import com.microsoft.windowsazure.mobileservices.authentication.MobileServiceAuthenticationProvider;
import com.microsoft.windowsazure.mobileservices.authentication.MobileServiceUser;
import com.microsoft.windowsazure.mobileservices.http.NextServiceFilterCallback;
import com.microsoft.windowsazure.mobileservices.http.ServiceFilter;
import com.microsoft.windowsazure.mobileservices.http.ServiceFilterRequest;
import com.microsoft.windowsazure.mobileservices.http.ServiceFilterResponse;

import java.io.File;
import java.io.FileInputStream;
import java.net.MalformedURLException;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
//import java.util.HashMap;


//import com.android.volley.DefaultRetryPolicy;
//import com.android.volley.RequestQueue;
//import com.android.volley.Response;
//import com.android.volley.VolleyError;
//import com.android.volley.toolbox.Volley;

/**
 * Created by jdella on 6/20/2016.
 */
public class AzureMobileServiceHelper {

    private static final String mAzURL = "https://acaad.azurewebsites.net";
    private static final String mBlobURL = "https://acastore1.blob.core.windows.net/signatures/";
    private static final String mStoreName = "acastore1";
    private static final String mStoreContainer = "signatures";
    private static final String mStoreKey = "STHfTjuQNZuDhOSGc51Ftcb+HqjIqmakELFwoNEDhtFcLdauAmhQ4CddDW7hLrqYauj+reOVLvn5vCuaL7v3/A==";
    private static final String storageConnectionString = "DefaultEndpointsProtocol=http;" + "AccountName="+mStoreName+";"+ "AccountKey="+mStoreKey;

    private static String mUID;
    private static String mTKN;

    private static Context mContext;
    protected static MobileServiceClient mClient;

    public boolean bAuthenticating = false;
    public final Object mAuthenticationLock = new Object();

    private boolean mDelayedLogin = false;

    private static int NUMATTEMPTS = 4;

    public AzureMobileServiceHelper(Context c, String uid, String tkn, boolean delayedLogin){
        mContext = c;
        mUID = uid;
        mTKN = tkn;
        mDelayedLogin = delayedLogin;
        InitClient();
    }

    public void InitClient(){
        if (mClient == null)
            try {
                mClient = new MobileServiceClient(
                        mAzURL, mContext)
                        .withFilter(new ProgressFilter())
                        .withFilter(new RefreshTokenCacheFilter());
                if (!mDelayedLogin)
                    authenticate(false, null, null);
            } catch (MalformedURLException e) {
                ShowDebugLog("Error creating the Mobile Service.");
            }
    }

    /**
     * Loop to see if authentication is still in progress, limits errors for multiple login attempts from the same client
     */
    public boolean detectAndWaitForAuthentication()
    {
        boolean detected = false;
        synchronized(mAuthenticationLock)
        {
            do
            {
                if (bAuthenticating == true)
                    detected = true;
                try
                {
                    mAuthenticationLock.wait(1000);
                }
                catch(InterruptedException e)
                {}
            }
            while(bAuthenticating == true);
        }
        if (bAuthenticating == true)
            return true;

        return detected;
    }


    /**
     * Waits for authentication to complete then adds or updates the token
     * in the X-ZUMO-AUTH request header.
     *
     * @param request      * The request that receives the updated token.
     */
    private void waitAndUpdateRequestToken(ServiceFilterRequest request)
    {
        MobileServiceUser user = null;
        if (detectAndWaitForAuthentication())
        {
            user = mClient.getCurrentUser();
            if (user != null)
            {
                request.removeHeader("X-ZUMO-AUTH");
                request.addHeader("X-ZUMO-AUTH", user.getAuthenticationToken());
            }
        }
    }

    /**
     * Authenticates with the desired login provider. Also caches the token.
     *
     * If a local token cache is detected, the token cache is used instead of an actual
     * login unless bRefresh is set to true forcing a refresh.
     *
     * @param bRefreshCache * Indicates whether to force a token refresh.
     */
    public void authenticate(final boolean bRefreshCache, final Runnable runOnSucess, final Runnable runOnFail) {

        bAuthenticating = true;

        if (bRefreshCache || !loadUserTokenCache(mClient)){
            ShowDebugLog("Logging into Azure Mobile Service");

            final ListenableFuture<MobileServiceUser> mLogin = mClient.login(MobileServiceAuthenticationProvider.WindowsAzureActiveDirectory);

            Futures.addCallback(mLogin, new FutureCallback<MobileServiceUser>() {
                @Override
                public void onFailure(Throwable exc) {
                    ShowDebugLog("Authentication Error: " + exc.getMessage());

                    //REMAIN PERSISTENT IF USER TRIES TO ESCAPE OUT OF LOGIN
                    if (exc.getLocalizedMessage().equals("User Canceled"))
                        authenticate(true, runOnSucess, runOnFail);

                    //RUN AFTER SUCCESSFUL LOGIN
                    if (runOnFail != null)
                        (new Handler()).postDelayed(runOnFail, 1000);

                    bAuthenticating = false;
                    mAuthenticationLock.notifyAll();
                }

                @Override
                public void onSuccess(MobileServiceUser user) {
                    synchronized (mAuthenticationLock) {
                        ShowDebugLog("You are now logged in as " + user.getUserId());
                        //RUN AFTER SUCCESSFUL LOGIN
                        if (runOnSucess != null)
                            (new Handler()).postDelayed(runOnSucess, 1000);

                        mUID = user.getUserId();
                        mTKN = user.getAuthenticationToken();

                        bAuthenticating = false;
                        mAuthenticationLock.notifyAll();
                    }
                }
            });
        } else {
            // OTHER THREADS MAY BE BLOCKED WAITING TO BE NOTIFIED WHEN
            // AUTHENTICATION IS COMPLETE.
            synchronized(mAuthenticationLock)
            {
                bAuthenticating = false;
                mAuthenticationLock.notifyAll();

                //RUN AFTER SUCCESSFUL LOGIN
                if (runOnSucess != null)
                    (new Handler()).postDelayed(runOnSucess, 1000);
            }
        }
    }

    public static final String TAG = "AZURE HELPER DEBUG";
    protected static void ShowDebugLog(String msg){
        Log.d(TAG, msg);
    }

    /**
     * Filter to use visual queues of progress.
     */
    private class ProgressFilter implements ServiceFilter {
        @Override
        public ListenableFuture<ServiceFilterResponse> handleRequest(ServiceFilterRequest request, NextServiceFilterCallback nextServiceFilterCallback) {

            final SettableFuture<ServiceFilterResponse> resultFuture = SettableFuture.create();
            ListenableFuture<ServiceFilterResponse> future = nextServiceFilterCallback.onNext(request);
            Futures.addCallback(future, new FutureCallback<ServiceFilterResponse>() {
                @Override
                public void onFailure(Throwable e) { resultFuture.setException(e); }

                @Override
                public void onSuccess(ServiceFilterResponse response) { resultFuture.set(response); }
            });
            return resultFuture;
        }
    }

    /**
     * The RefreshTokenCacheFilter class filters responses for HTTP status code 401.
     * When 401 is encountered, the filter calls the authenticate method on the
     * UI thread. Out going requests and retries are blocked during authentication.
     * Once authentication is complete, the token cache is updated and
     * any blocked request will receive the X-ZUMO-AUTH header added or updated to
     * that request.
     */
    private class RefreshTokenCacheFilter implements ServiceFilter {

        AtomicBoolean mAtomicAuthenticatingFlag = new AtomicBoolean();

        @Override
        public ListenableFuture<ServiceFilterResponse> handleRequest(
                final ServiceFilterRequest request,
                final NextServiceFilterCallback nextServiceFilterCallback
        )
        {
            // IF AUTHENTICATION IS ALREADY IN PROGRESS BLOCK THE REQUEST
            // UNTIL AUTHENTICATION IS COMPLETE TO AVOID UNNECESSARY AUTHENTICATIONS AS
            // A RESULT OF HTTP STATUS CODE 401.
            // IF AUTHENTICATION WAS DETECTED, ADD THE TOKEN TO THE REQUEST.
            waitAndUpdateRequestToken(request);

            // SEND THE REQUEST DOWN THE FILTER CHAIN
            // RETRYING UP TO NUMATTEMPTS TIMES ON 401 RESPONSE CODES.
            ListenableFuture<ServiceFilterResponse> future = null;
            ServiceFilterResponse response = null;
            int responseCode = 401;
            for (int i = 0; (i < NUMATTEMPTS ) && (responseCode == 401); i++)
            {
                future = nextServiceFilterCallback.onNext(request);
                try {
                    response = future.get();
                    responseCode = response.getStatus().code;
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (ExecutionException e) {
                    if (e.getCause().getClass() == MobileServiceException.class)
                    {
                        MobileServiceException mEx = (MobileServiceException) e.getCause();
                        responseCode = mEx.getResponse().getStatus().code;
                        if (responseCode == 401)
                        {
                            // TWO SIMULTANEOUS REQUESTS FROM INDEPENDENT THREADS COULD GET HTTP STATUS 401.
                            // PROTECTING AGAINST THAT RIGHT HERE SO MULTIPLE AUTHENTICATION REQUESTS ARE
                            // NOT SETUP TO RUN ON THE UI THREAD.
                            // WE ONLY WANT TO AUTHENTICATE ONCE. REQUESTS SHOULD JUST WAIT AND RETRY
                            // WITH THE NEW TOKEN.
                            if (mAtomicAuthenticatingFlag.compareAndSet(false, true))
                            {
                                // AUTHENTICATE ON UI THREAD
                                ((Activity)mContext).runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        // FORCE A TOKEN REFRESH DURING AUTHENTICATION.
                                        authenticate(true, null, null);
                                    }
                                });
                            }

                            // WAIT FOR AUTHENTICATION TO COMPLETE THEN UPDATE THE TOKEN IN THE REQUEST.
                            waitAndUpdateRequestToken(request);
                            mAtomicAuthenticatingFlag.set(false);
                        }
                    }
                }
            }
            return future;
        }
    }

    private boolean loadUserTokenCache(MobileServiceClient m){

        boolean b = true;
        if (mUID != null | mTKN != null){
            MobileServiceUser user = new MobileServiceUser(mUID);
            user.setAuthenticationToken(mTKN);
            m.setCurrentUser(user);
            b = false;
        }
        return b;
    }

    // NEEDS TO BE SET ON THE ACTIVITY WHERE LOG IN WILL BE SHOWN
    protected void SetContext(Context c){
        this.mContext = c;
        mClient.setContext(mContext);
        if (mClient == null)
            InitClient();
    }


    public static String getmBlobURL() {
        return mBlobURL;
    }

    public static class BlobObj {
        String mHash;
        File mFile;
        String mType;
        String mRef;

        BlobObj(String h, File f, String t, String r) {
            this.mHash = h;
            this.mFile = f;
            this.mType = t;
            this.mRef = r;
        }
    }

    protected static class UploadBlob extends AsyncTask<BlobObj, Integer, String> {

        private Boolean mErr = false;

        @Override
        protected String doInBackground(BlobObj... params) {
            try {
                CloudStorageAccount storageAccount = CloudStorageAccount.parse(storageConnectionString);
                CloudBlobClient blobClient = storageAccount.createCloudBlobClient();

                CloudBlobContainer container = blobClient.getContainerReference(mStoreContainer);
                BlobContainerPermissions containerPermissions = new BlobContainerPermissions();
                containerPermissions.setPublicAccess(BlobContainerPublicAccessType.CONTAINER);
                container.uploadPermissions(containerPermissions);

                CloudBlockBlob blob = container.getBlockBlobReference(params[0].mHash);
                blob.upload(new FileInputStream(params[0].mFile), params[0].mFile.length());

            } catch (Exception e) {
                mErr = true;
                ShowDebugLog("UPLOAD ERROR: " + e.getMessage());
                //SendFailedUploadEmail(params[0]);
            }
            return params[0].mFile.getAbsolutePath();
        }

        @Override
        protected void onPostExecute(String s) {
            super.onPostExecute(s);

            ShowDebugLog("File " + s + " uploaded!");
            File file = new File(s);

            if (!mErr) {
                file.delete();
                ShowDebugLog("File " + s + " deleted! (onPostExecute)");
            }
        }
    }

//    protected static void SendFailedUploadEmail(final BlobObj b) {
//        // Instantiate the RequestQueue.
//        RequestQueue queue = Volley.newRequestQueue(mContext);
//        String url =  "https://api.mailgun.net/v3/autocan.mailgun.org/messages";
//
//        HashMap<String,String> mailgun =  new HashMap<String,String>();
//        mailgun.put("from", "noreply@autocan.ca");
//        mailgun.put("to", "appdev@autocan.ca");
//        mailgun.put("subject", "Error Uploading File to Storage ref: " + b.mRef + " type:" + b.mType);
//        mailgun.put("text", "File Attached");
//
//        MultipartRequest request = new MultipartRequest(
//                url,b.mFile,
//                new Response.Listener<String>() {
//                    @Override
//                    public void onResponse(String response) {
//                        b.mFile.delete();
//                        ShowDebugLog("File " + b.mFile.getAbsolutePath() + " deleted! (SendFailedUploadEmail)");
//                    }
//                },
//                new Response.ErrorListener() {
//                    @Override
//                    public void onErrorResponse(VolleyError error) {
//                        ShowDebugLog("File " + b.mFile.getAbsolutePath() + " fail over error: " + error.getLocalizedMessage());
//                    }
//                }, mailgun);
//        //set Retry Policy to handle mailgun unreachable
//        request.setRetryPolicy(new DefaultRetryPolicy(5000,3,DefaultRetryPolicy.DEFAULT_BACKOFF_MULT));
//        queue.add(request);
//    }
}
