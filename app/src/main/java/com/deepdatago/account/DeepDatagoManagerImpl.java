package com.deepdatago.account;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.BottomNavigationView;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.MenuItem;
import android.widget.TextView;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.RequestFuture;
import com.android.volley.toolbox.Volley;
import com.deepdatago.crypto.CryptoManager;
import com.deepdatago.crypto.CryptoManagerImpl;
import com.deepdatago.provider.CryptoProvider;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.awesomeapp.messenger.MainActivity;
import org.awesomeapp.messenger.provider.Imps;
import org.ethereum.geth.Geth;
import org.ethereum.geth.KeyStore;
import org.ethereum.geth.Account;
import org.ethereum.geth.Accounts;
import org.ethereum.geth.EthereumClient;
import org.ethereum.geth.Context;
import org.ethereum.geth.Node;
import org.ethereum.geth.NodeConfig;
import org.ethereum.geth.Address;
import org.ethereum.geth.BigInt;
import org.ethereum.geth.Transaction;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;
import com.squareup.okhttp.*;
import com.squareup.okhttp.MediaType;

/**
 * Created by tnnd on 7/5/18.
 */

public class DeepDatagoManagerImpl implements DeepDatagoManager {
    private static ContentResolver sContentResolver = null;
    private static java.io.File sFileDirectory = null;

    private KeyStore mKeyStore = null;
    private NodeConfig mNodeConfig = new NodeConfig();
    // private Node mNode = null;
    private CryptoManager mCryptoManager = null;
    private String mSymmetricKeyForAllFriends = null; // "63A78349DF7544768E0ECBCF3ACB6527";
    private final String mKeyStoreName = "keystore";
    private final String mPublicServerAddress = "0xce66ae967e95f6f90defa8b58e6ab4a721c3c7fb"; // a server address, can be changed later
    private final String mGethNodeDir = ".eth1";
    private final int HTTP_REQUEST_TIMEOUT_IN_SECONDS = 10;
    private static DeepDatagoManager msDeepDatagoManager = null;

    private DeepDatagoManagerImpl() {
        if (sFileDirectory == null || sContentResolver == null)
            return;

        this.mKeyStore = new KeyStore(sFileDirectory + "/" + this.mKeyStoreName, Geth.LightScryptN, Geth.LightScryptP);
        // this.mCreationPassword = creationPassword;
        this.mSymmetricKeyForAllFriends = getSharedKeyForAllFriends();

        this.mCryptoManager = CryptoManagerImpl.getInstance();
        this.mNodeConfig.setEthereumNetworkID(1);
        /*
        BigInt chain = new BigInt(this.mNodeConfig.getEthereumNetworkID());

        try {
            // Node node = Geth.newNode(getFilesDir() + "/keystore", nodeConfig);
            this.mNode = Geth.newNode(sFileDirectory + "/" + this.mGethNodeDir, this.mNodeConfig);
            this.mNode.start();
        } catch (Exception e) {
            // transactionStr = e.getMessage();
            // e.printStackTrace();
            // it is okay that the node is started before
        }
        */

    }

    public static DeepDatagoManager getInstance() {
        if (msDeepDatagoManager == null) {
            synchronized (DeepDatagoManagerImpl.class) {
                if(msDeepDatagoManager == null) {
                    msDeepDatagoManager = new DeepDatagoManagerImpl();
                }
            }
            return msDeepDatagoManager;
        }
        return msDeepDatagoManager;
    }
    /*
    public static DeepDatagoManager getInstance(String password) {
        DeepDatagoManager accountManage = DeepDatagoManagerImpl.getInstance();
        accountManage.saveAccountPassword(password);
        return accountManage;
    }
    */

    private Account getAccount() {
        // TODO Load mSymmetricKeyForAllFriends from database
        try {
            Account account = null;
            Accounts accounts = this.mKeyStore.getAccounts();
            if (accounts.size() <= 0) {
                return null;
            }
            account = accounts.get(0);
            return account;

            /*
            if (this.mCreationPassword != null) {
                this.mKeyStore.unlock(newAccount, this.mCreationPassword);
            }
            */
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private Account createAccount(String password, KeyStore keyStore) {
        if (password.length() == 0) {
            return null;
        }

        try {
            Accounts accounts = keyStore.getAccounts();
            if (accounts.size() <= 0) {
                return this.mKeyStore.newAccount(password);
            }
            return getAccount();
            /*
            if (this.mCreationPassword != null) {
                this.mKeyStore.unlock(newAccount, this.mCreationPassword);
            }
            */

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public String registerRequest(String password, String userNickName) {
        String transactionStr = null;
        Account account = createAccount(password, this.mKeyStore);

        getSharedKeyForAllFriends();

        if (account == null) {
            return null;
        }
        try {
            // System.out.println("to_address: " + account.getAddress().getHex());
            Node node = Geth.newNode(sFileDirectory + "/" + this.mGethNodeDir, this.mNodeConfig);
            node.start();

            String data = this.mCryptoManager.getPublicKeyString();
            // System.out.println("public key: " + data);
            transactionStr = signTransaction(account, password, data.getBytes("UTF8"));
            node.stop();
            // System.out.println("register input length: " + transactionStr.length() + " string: " + transactionStr);
            JSONObject requestNode = new JSONObject();

            String encryptedName = this.mCryptoManager.encryptStringWithSymmetricKey(this.mSymmetricKeyForAllFriends, userNickName);

            requestNode.put(Tags.NAME, encryptedName);
            requestNode.put(Tags.TRANSACTION, transactionStr);
            requestNode.put(Tags.SENDER_ADDRESS, account.getAddress().getHex());

            String url = Tags.BASE_URL + Tags.ACCOUNT_REGISTER_API;
            JSONObject response = sendPostRequestSync(url, requestNode);
            if (response == null) {
                // error occurred
                return null;
            }
            String xmppUsername = response.getString(Tags.XMPP_ACCOUNT_NUMBER).toLowerCase() + "@" + Tags.BASE_SERVER_ADDRESS;
            String xmppPassword = response.getString(Tags.XMPP_ACCOUNT_PASSWORD);

            ContentValues accountValue = new ContentValues(2); // we only store user name and password
            accountValue.put(Tags.DB_FIELD_XMPP_USER_NAME, xmppUsername);
            accountValue.put(Tags.DB_FIELD_XMPP_PASSOWRD, xmppPassword);
            sContentResolver.update(Tags.CRYPTO_ACCOUNT_URI, accountValue, "_ID=1", null);
            return response.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public String signTransaction(Account account, String password, byte[] dataBytes) {
        long nonce;
        double amount = 0;
        long gasLimit = 0;
        double gasPrice = 0;

        if (account == null || password == null || dataBytes == null || dataBytes.length == 0) {
            return null;
        }
        BigInt chain = new BigInt(this.mNodeConfig.getEthereumNetworkID());
        String returnStr = null;

        try {
            this.mKeyStore.unlock(account, password);

            // nonce = this.node.getEthereumClient().getPendingNonceAt(context, account.getAddress());
            nonce = 0;
            Transaction tx = new Transaction(
                    (long) nonce,
                    new Address(this.mPublicServerAddress),
                    new BigInt((long) amount),
                    gasLimit, // new BigInt((long) gasLimit),
                    new BigInt((long) gasPrice),
                    dataBytes);

            Transaction signed = this.mKeyStore.signTx(account, tx, chain);
            returnStr = signed.encodeJSON();
            // Transaction newTrans = Geth.newTransactionFromJSON(returnStr);
            // newTrans.getFrom(chain);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        finally {
            try {
                this.mKeyStore.lock(account.getAddress());
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

        return returnStr;
    }

    public JSONArray getSummary(String requestAccount, android.content.Context contextForHTTP) {

        long unixTime = System.currentTimeMillis() / 1000L;
        String timeString = Long.toString(unixTime);

        // String transactionStr = b64EncryptedSignedBytes(timeString.getBytes());
        String signedTimeString = this.mCryptoManager.signStrWithPrivateKey(timeString, true);
        if (signedTimeString == null || signedTimeString.length() == 0) {
            return null;
        }

        String lURL = Tags.BASE_URL + Tags.REQUEST_SUMMARY_API;

        if (requestAccount == null) {
            requestAccount = getAccount().getAddress().getHex();
        }

        lURL += Tags.TO_ADDRESS + "=" + requestAccount + "&";
        lURL += Tags.TIME_STAMP + "=" + timeString + "&";
        lURL += Tags.ENCODED_SIGNATURE + "=" + signedTimeString;

        JSONObject responseObject = sendGetRequestSync(lURL);
        if (responseObject == null) {
            return null;
        }
        JSONArray returnArray = new JSONArray();
        try {
            JSONArray friendReqArray = responseObject.getJSONArray("friend_request");
            if (friendReqArray.length() == 0) {
                return null;
            }

            PrivateKey privateKey = this.mCryptoManager.getPrivateKey();

            for (int i = 0; i < friendReqArray.length(); i++) {
                JSONObject object = friendReqArray.getJSONObject(i);
                String name = object.getString(Tags.NAME);
                String fromAddress = object.getString(Tags.FROM_ADDRESS).replace("0x", "").toLowerCase();
                String requestStr = object.getString(Tags.REQUEST);
                requestStr = requestStr.replace("\\\"", "\"");
                JSONObject keyObject = new JSONObject(requestStr);
                String friendAESKey = keyObject.getString(Tags.FRIEND_SYMMETRIC_KEY);
                String allFriendsAESKey = keyObject.getString(Tags.ALL_FRIENDS_SYMMETRIC_KEY);
                allFriendsAESKey = this.mCryptoManager.decryptStrWithPrivateKey(privateKey, allFriendsAESKey);
                friendAESKey = this.mCryptoManager.decryptStrWithPrivateKey(privateKey, friendAESKey);
                name = this.mCryptoManager.decryptStringWithSymmetricKey(allFriendsAESKey, name);

                ContentValues accountValue = new ContentValues(3);
                accountValue.put(Tags.DB_FIELD_PRIVATE_SYMMETRIC_KEY, friendAESKey);
                accountValue.put(Tags.DB_FIELD_SHARED_SYMMETRIC_KEY, allFriendsAESKey);
                accountValue.put(Tags.DB_FIELD_ACCOUNT, fromAddress);

                final String[] projection = { Tags.DB_FIELD_ACCOUNT };
                String selection = Tags.DB_FIELD_ACCOUNT + "='" + fromAddress + "'";
                Cursor c = sContentResolver.query(Tags.CRYPTO_FRIENDS_KEYS_URI, projection, selection, null, null);
                int cursorCount = c.getCount();
                if (cursorCount > 0) {
                    sContentResolver.update(Tags.CRYPTO_FRIENDS_KEYS_URI, accountValue, selection, null);
                }
                else {
                    sContentResolver.insert(Tags.CRYPTO_FRIENDS_KEYS_URI, accountValue);
                }
                c.close();

                // if (fromAddress.replace("0x", "").equalsIgnoreCase(requestAccount)) {
                JSONObject returnObj = new JSONObject();
                returnObj.put(Tags.NAME, name);
                returnObj.put(Tags.FROM_ADDRESS, fromAddress);
                returnArray.put(i, returnObj);
                // }

            }

        } catch (JSONException e)
        {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }


        return returnArray;
    }

    public void getApprovedDetails(String toAddress, android.content.Context contextForHTTP) {

        long unixTime = System.currentTimeMillis() / 1000L;
        String timeString = Long.toString(unixTime);

        // String transactionStr = b64EncryptedSignedBytes(timeString.getBytes());
        String signedTimeString = this.mCryptoManager.signStrWithPrivateKey(timeString, true);
        if (signedTimeString == null || signedTimeString.length() == 0) {
            return;
        }

        Account account = getAccount();
        String fromAddress = account.getAddress().getHex();


        String lURL = Tags.BASE_URL + Tags.APPROVED_DETAILS_API;

        lURL += Tags.FROM_ADDRESS + "=" + fromAddress.toLowerCase() + "&";
        lURL += Tags.TO_ADDRESS + "=0x" + toAddress.toLowerCase() + "&"; // toAddess has 0x already
        lURL += Tags.TIME_STAMP + "=" + timeString + "&";
        lURL += Tags.ENCODED_SIGNATURE + "=" + signedTimeString;

        JSONObject responseObject = sendGetRequestSync(lURL);
        if (responseObject == null) {
            return;
        }
        JSONArray returnArray = new JSONArray();
        Cursor c = null;
        try {
            String approvedRequestStr = responseObject.getString("approved_request");
            JSONObject approvedRequestObject = new JSONObject(approvedRequestStr);
            String key = approvedRequestObject.getString("all_friends_symmetric_key");


            // String key = friendReqObject.getString("all_friends_symmetric_key");

            PrivateKey privateKey = this.mCryptoManager.getPrivateKey();
            String allFriendsAESKey = this.mCryptoManager.decryptStrWithPrivateKey(privateKey, key);
            ContentValues accountValue = new ContentValues(2);
            accountValue.put(Tags.DB_FIELD_SHARED_SYMMETRIC_KEY, allFriendsAESKey);
            accountValue.put(Tags.DB_FIELD_ACCOUNT, toAddress);
            final String[] projection = { Tags.DB_FIELD_ACCOUNT };
            String selection = Tags.DB_FIELD_ACCOUNT + "='" + toAddress + "'";
            c = sContentResolver.query(Tags.CRYPTO_FRIENDS_KEYS_URI, projection, selection, null, null);
            int cursorCount = c.getCount();
            if (cursorCount > 0) {
                sContentResolver.update(Tags.CRYPTO_FRIENDS_KEYS_URI, accountValue, selection, null);
            }


            /*
            for (int i = 0; i < friendReqArray.length(); i++) {
                JSONObject object = friendReqArray.getJSONObject(i);
                String requestStr = object.getString(Tags.ALL_FRIENDS_SYMMETRIC_KEY);
                // requestStr = requestStr.replace("\\\"", "\"");
                JSONObject keyObject = new JSONObject(requestStr);

                String allFriendsAESKey = keyObject.getString(Tags.ALL_FRIENDS_SYMMETRIC_KEY);
                */
                /*
                allFriendsAESKey = this.mCryptoManager.decryptTextBase64(privateKey, allFriendsAESKey.getBytes());

                ContentValues accountValue = new ContentValues(2);
                accountValue.put(Tags.DB_FIELD_SHARED_SYMMETRIC_KEY, allFriendsAESKey);
                accountValue.put(Tags.DB_FIELD_ACCOUNT, fromAccount);

                final String[] projection = { Tags.DB_FIELD_ACCOUNT };
                String selection = Tags.DB_FIELD_ACCOUNT + "='" + fromAccount + "'";
                Cursor c = sContentResolver.query(Tags.CRYPTO_FRIENDS_KEYS_URI, projection, selection, null, null);
                int cursorCount = c.getCount();
                if (cursorCount > 0) {
                    sContentResolver.update(Tags.CRYPTO_FRIENDS_KEYS_URI, accountValue, selection, null);
                }
                */
                /*
                else {
                    sContentResolver.insert(Tags.CRYPTO_FRIENDS_KEYS_URI, accountValue);
                }
                */

            // }


        } catch (JSONException e)
        {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (c!=null) {
                c.close();
            }
        }

    }

    private JSONObject sendGetRequestSync(String iURL) {
        OkHttpClient client = new OkHttpClient();

        com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                .url(iURL)
                .build();
        try {
            Response response = client.newCall(request).execute();
            String responseStr = response.body().string();
            JSONObject responseObj = new JSONObject(responseStr);
            return responseObj;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        /*
        RequestFuture<JSONObject> requestFuture=RequestFuture.newFuture();
        JsonObjectRequest request = new JsonObjectRequest(Request.Method.GET,
                iURL,new JSONObject(),requestFuture,requestFuture);
        RequestQueue queue = Volley.newRequestQueue(contextForHTTP);
        queue.add(request);

        JSONObject responseObject = null;

        try {
            responseObject = requestFuture.get(HTTP_REQUEST_TIMEOUT_IN_SECONDS,TimeUnit.SECONDS);
            return responseObject;
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            e.printStackTrace();
        }
        */
        return null;
    }

    private JSONObject sendPostRequestSync(String iURL, JSONObject iBodyContent) {
        OkHttpClient client = new OkHttpClient();

        if (iBodyContent == null) {
            return null;
        }

        final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");
        RequestBody body = RequestBody.create(JSON_MEDIA_TYPE, iBodyContent.toString());

        com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                .url(iURL)
                .post(body)
                .build();
        try {
            Response response = client.newCall(request).execute();
            if (response.code() != 200) {
                return null;
            }
            String responseStr = response.body().string();
            JSONObject responseObj = new JSONObject(responseStr);
            return responseObj;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /*
    private String loadPublicKey() {
        // check if mFileDir + /keystore + keyname exists
        String publicKeyName = sFileDirectory + "/" + this.mKeyStoreName + "/" + this.mPublicKeyName;
        File publicKeyFile = new File(publicKeyName);
        if (! publicKeyFile.exists()) {
            String privateKeyName = sFileDirectory + "/" + this.mKeyStoreName + "/" + this.mPrivateKeyName;
            this.mCryptoManager.generateKeyPair(privateKeyName, publicKeyName, null);
        }
        String publicKeyContent = null;
        try {
            publicKeyContent = getStringFromFile(publicKeyName);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return publicKeyContent;
    }

    private String getStringFromFile (String filePath) throws Exception {
        File fl = new File(filePath);
        FileInputStream fin = new FileInputStream(fl);
        String ret = convertStreamToString(fin);
        //Make sure you close all streams.
        fin.close();
        return ret;
    }

    private String convertStreamToString(InputStream is) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
    }
    */

    public String getSharedKeyForAllFriends()
    {
        if (sContentResolver == null) {
            return null;
        }
        // ContentResolver lResolver = new ContentResolver
        final String[] projection = { Tags.DB_FIELD_SHARED_SYMMETRIC_KEY};
        String selection = Tags.DB_FIELD_PRIMARY_ID + "=1";
        Cursor acct = sContentResolver.query(Tags.CRYPTO_ACCOUNT_URI, projection, selection, null, null);

        String symmetricKey = null;
        if (acct.getCount() == 0)
        {
            ContentValues accountValue = new ContentValues(1);
            // contactListValues.put(Imps.ContactList.NAME, list.getName());
            UUID idOne = UUID.randomUUID();
            symmetricKey = idOne.toString().replace("-", "");

            accountValue.put(Tags.DB_FIELD_SHARED_SYMMETRIC_KEY, symmetricKey);

            Uri uri = null;
            uri = sContentResolver.insert(Tags.CRYPTO_ACCOUNT_URI, accountValue);
            acct.close();
            return symmetricKey;
        }

        int index = acct.getColumnIndex(Tags.DB_FIELD_SHARED_SYMMETRIC_KEY);
        acct.moveToFirst();
        symmetricKey = acct.getString(index);
        acct.close();

        return symmetricKey;
    }

    public static void initStaticMembers(ContentResolver iContentResolver, java.io.File iFileDirectory) {
        if (sContentResolver != null || sFileDirectory != null) {
            return;
        }
        sContentResolver = iContentResolver;
        sFileDirectory = iFileDirectory;
        CryptoManagerImpl.initStaticMembers(iFileDirectory);
        DeepDatagoManagerImpl.getInstance();
    }
    /*
    public void saveAccountPassword(String password) {
        if (sContentResolver == null) {
            return;
        }
        this.mCreationPassword = password;
        String selection = "_ID=1";
        Cursor account = sContentResolver.query(Tags.CRYPTO_ACCOUNT_URI, null, selection, null, null);
        int acctCount = account.getCount();

        ContentValues accountValue = new ContentValues(1);
        accountValue.put(Tags.DB_FIELD_PASSOWRD, password);

        if (acctCount == 0)
        {

            Uri uri = null;
            uri = sContentResolver.insert(Tags.CRYPTO_ACCOUNT_URI, accountValue);
        }
        else {
            int updateCount = sContentResolver.update(Tags.CRYPTO_ACCOUNT_URI, accountValue, selection, null);
        }

    }
    */
    public String getAllFriendsKey(String friendId)
    {
        JSONObject keysObj = getFriendKeys(friendId);
        try {
            if (keysObj != null) {
                String friendSharedKey = keysObj.getString(Tags.ALL_FRIENDS_SYMMETRIC_KEY);
                return friendSharedKey;
            }
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return null;
    }

    public String getSymmetricKey(String accountId)
    {
        String symmetricKey = null;

        JSONObject keysObj = getFriendKeys(accountId);
        Cursor c = null;
        try {
            if (keysObj != null) {
                String friendSymmetricKey = keysObj.getString(Tags.FRIEND_SYMMETRIC_KEY);
                return friendSymmetricKey;
            }
            if (sContentResolver == null) {
                return null;
            }
            UUID idOne = UUID.randomUUID();
            symmetricKey = idOne.toString().replace("-", "");

            ContentValues accountValue = new ContentValues(3);
            accountValue.put(Tags.DB_FIELD_PRIVATE_SYMMETRIC_KEY, symmetricKey);
            accountValue.put(Tags.DB_FIELD_SHARED_SYMMETRIC_KEY, ""); // shared symmetric key will be available after approve the friend request
            accountValue.put(Tags.DB_FIELD_ACCOUNT, accountId);

            final String[] projection = { Tags.DB_FIELD_ACCOUNT };
            String selection = Tags.DB_FIELD_ACCOUNT + "='" + accountId + "'";
            c = sContentResolver.query(Tags.CRYPTO_FRIENDS_KEYS_URI, projection, selection, null, null);
            int cursorCount = c.getCount();
            if (cursorCount > 0) {
                sContentResolver.update(Tags.CRYPTO_FRIENDS_KEYS_URI, accountValue, selection, null);
            }
            else {
                sContentResolver.insert(Tags.CRYPTO_FRIENDS_KEYS_URI, accountValue);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            if (c != null) {
                c.close();
            }
        }



        return symmetricKey;
    }

    private String getAccountPassword() {
        if (sContentResolver == null) {
            return null;
        }
        // sContentResolver.delete(Imps.Contacts.CRYPTO_ACCOUNT_URI,	"_id=1",null);

        final String[] projection = { Tags.DB_FIELD_PASSOWRD};
        Cursor account = sContentResolver.query(Tags.CRYPTO_ACCOUNT_URI, projection, null, null, null);

        if (account.getCount() == 1) {
            int index = account.getColumnIndex(Tags.DB_FIELD_PASSOWRD);

            account.moveToFirst();
            String password = account.getString(index);
            account.close();
            return password;

        }
        account.close();
        return null;
    }

    private String b64EncryptedSignedBytes(byte[] inputBytes)
    {
        String transactionStr = null;
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            PrivateKey privateKey = this.mCryptoManager.getPrivateKey();

            sig.initSign(privateKey);
            sig.update(inputBytes);
            byte[] signatureBytes = sig.sign();
            transactionStr = new String(Base64.encode(signatureBytes, Base64.DEFAULT));
            transactionStr = URLEncoder.encode(transactionStr,"UTF-8");
            return transactionStr;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public JSONObject getFriendKeys(String account) {
        if (sContentResolver == null) {
            return null;
        }

        final String[] projection = { Tags.DB_FIELD_SHARED_SYMMETRIC_KEY, Tags.DB_FIELD_PRIVATE_SYMMETRIC_KEY};
        final String selection = Tags.DB_FIELD_ACCOUNT + "='" + account.toLowerCase() + "'";
        Cursor keysCursor = sContentResolver.query(Tags.CRYPTO_FRIENDS_KEYS_URI, null, selection, null, null);

        if (keysCursor.getCount() == 1) {
            keysCursor.moveToFirst();

            int index = keysCursor.getColumnIndex(Tags.DB_FIELD_PRIVATE_SYMMETRIC_KEY);
            String privateSymmKey = keysCursor.getString(index);
            index = keysCursor.getColumnIndex(Tags.DB_FIELD_SHARED_SYMMETRIC_KEY);
            String sharedSymmKey = keysCursor.getString(index);

            JSONObject returnObj = new JSONObject();
            try {
                returnObj.put(Tags.ALL_FRIENDS_SYMMETRIC_KEY, sharedSymmKey);
                returnObj.put(Tags.FRIEND_SYMMETRIC_KEY, privateSymmKey);
                return returnObj;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            } finally {
                keysCursor.close();
            }
        }
        else {
            keysCursor.close();
        }

        return null;
    }

    public PublicKey getPublicKey(String address) {
        String lURL = Tags.BASE_URL + Tags.GET_PUBLIC_KEY_API;
        lURL += address.toUpperCase() + "/";

        JSONObject responseObject = sendGetRequestSync(lURL);
        if (responseObject != null) {
            try {
                String publicKey = responseObject.getString(Tags.PUBLIC_KEY);
                if (publicKey != null) {
                    // remove 2
                    // first end of line
                    if (publicKey.charAt(publicKey.length()-1) == '\n') {
                        publicKey = publicKey.substring(0, publicKey.length() - 1);
                    }
                    int firstEOL = publicKey.indexOf('\n');
                    int secondEOL = publicKey.lastIndexOf('\n');
                    String publicKey2 = publicKey.substring(firstEOL+1, secondEOL);

                    PublicKey lPublicKey = this.mCryptoManager.loadPublicKeyFromRSAPEMString(publicKey2);
                    return lPublicKey;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        return null;
    }

    public void friendRequestSync(final String toAccount, final int requestType) {
        // JSON structure of friend request:
        // {
        //   "action_type": 0, // or 1 to approve
        //   "to_address": "0x<to_address>",
        //   "from_address": "0x<from_address>"
        //   "keys": "{
        //      "friend_request_symmetric_key": "<public_key_encrypted symmetric key>",
        //        Note: this field is optional if to approve a friend request, as this is already exchanged
        //      "all_friends_symmetric_key": "<public_key_encrypted symmetric key>",
        //        Note: this public key is always using the one for to_address' public key
        //    }"
        // }

        try  {
            //Your code goes here
            PublicKey publicKey = getPublicKey(toAccount);
            CryptoManager cryptoManager = CryptoManagerImpl.getInstance();

            JSONObject kyesNode = new JSONObject();
            if (requestType == Tags.FriendRequest) {
                String privateFriendSymmetricKey = getSymmetricKey(toAccount);
                if (privateFriendSymmetricKey == null) {
                    return;
                }
                kyesNode.put(Tags.FRIEND_SYMMETRIC_KEY, cryptoManager.encryptStrWithPublicKey(publicKey, privateFriendSymmetricKey));
            }
            String allFriendsSharedKey = getSharedKeyForAllFriends();
            String encryptedAllFriendsKey = cryptoManager.encryptStrWithPublicKey(publicKey, allFriendsSharedKey);
            kyesNode.put(Tags.ALL_FRIENDS_SYMMETRIC_KEY, encryptedAllFriendsKey); // need to encrypt by public key
            // DeepDatagoManager DeepDatagoManager = DeepDatagoManagerImpl.getInstance();
            Account account = getAccount();
            String addressStr = account.getAddress().getHex();
            // String transactionStr = signTransaction(account, null, signedRequestNode.toString().getBytes("UTF8"));
            long unixTime = System.currentTimeMillis() / 1000L;
            String timeString = Long.toString(unixTime);

            PrivateKey privateKey = this.mCryptoManager.getPrivateKey();

            String signedTimeString = this.mCryptoManager.signStrWithPrivateKey(timeString, false);

            JSONObject requestNode = new JSONObject();
            requestNode.put(Tags.ACTION_TYPE, requestType);
            if (requestType == Tags.FriendRequest) {
                requestNode.put(Tags.FROM_ADDRESS, addressStr);
                requestNode.put(Tags.TO_ADDRESS, "0x" + toAccount);
            }
            else {
                // when approving friend request, the fromAddress should be the sender, and toAddress is this client
                requestNode.put(Tags.TO_ADDRESS, addressStr);
                requestNode.put(Tags.FROM_ADDRESS, "0x" + toAccount);
            }
            // requestNode.put(Tags.REQUEST, transactionStr);
            requestNode.put(Tags.TIME_STAMP, timeString);
            requestNode.put(Tags.ENCODED_SIGNATURE, signedTimeString);
            requestNode.put(Tags.KEYS, kyesNode.toString());

            String lURL = Tags.BASE_URL + Tags.FRIEND_REQUEST_API;

            JSONObject response = sendPostRequestSync(lURL, requestNode);
            if (response == null) {
                // error occurred
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean createGroupChat(String groupAddress, ArrayList<String> invitees) {
        Account account = getAccount();
        // String transactionStr = null;
        try {
            // System.out.println("from_address: " + account.getAddress().getHex());

            // replace data by public key
            long unixTime = System.currentTimeMillis() / 1000L;
            String timeString = Long.toString(unixTime);

            PrivateKey privateKey = this.mCryptoManager.getPrivateKey();

            String signedTimeString = this.mCryptoManager.signStrWithPrivateKey(timeString, false);

            // System.out.println("public key: " + data);
            // System.out.println("register input length: " + transactionStr.length() + " string: " + transactionStr);
            JSONObject requestNode = new JSONObject();
            requestNode.put(Tags.FROM_ADDRESS, account.getAddress().getHex());
            requestNode.put(Tags.GROUP_ADDRESS, groupAddress);
            requestNode.put(Tags.TIME_STAMP, timeString);
            // System.out.println("time stamp: " + timeString + " signed time stamp: " + signStringByPrivateKey(privateKey, timeString));
            requestNode.put(Tags.ENCODED_SIGNATURE, signedTimeString);

            // add inviteeList into JSONArray
            JSONObject inviteeDict = new JSONObject();
            String groupKey = getGroupKey(groupAddress);

            for (int i = 0; i < invitees.size(); ++i) {
                String inviteeAddress = invitees.get(i);
                inviteeAddress = getBlockChainIDFromAddress(inviteeAddress);
                String friendSharedSymmetricKey = getAllFriendsKey(inviteeAddress);
                String encryptedGroupKey = mCryptoManager.encryptStringWithSymmetricKey(friendSharedSymmetricKey, groupKey);
                inviteeDict.put(inviteeAddress, encryptedGroupKey);
            }

            requestNode.put(Tags.GROUP_INVITEE_LIST, inviteeDict.toString());

            String lURL = Tags.BASE_URL + Tags.REQUEST_GROUP_INVITE_API;

            JSONObject response = sendPostRequestSync(lURL, requestNode);
            if (response == null) {
                // error occurred
            }

        } catch (Exception e) {
            // transactionStr = e.getMessage();
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public String getGroupKey(String groupAddress)
    {
        if (sContentResolver == null) {
            return null;
        }
        String address = getBlockChainIDFromAddress(groupAddress);
        // ContentResolver lResolver = new ContentResolver
        final String[] projection = { Tags.DB_FIELD_GROUP_SYMMETRIC_KEY};
        String selection = Tags.DB_FIELD_GROUP_ADDRESS + "='" + address + "'";
        Cursor acct = sContentResolver.query(Tags.CRYPTO_GROUPS_KEYS_URI, projection, selection, null, null);

        String symmetricKey = null;
        if (acct.getCount() == 0)
        {
            ContentValues groupValue = new ContentValues(1); // only generate one record
            UUID idOne = UUID.randomUUID();
            symmetricKey = idOne.toString().replace("-", "");

            groupValue.put(Tags.DB_FIELD_GROUP_SYMMETRIC_KEY, symmetricKey);
            groupValue.put(Tags.DB_FIELD_GROUP_ADDRESS, address);

            Uri uri = null;
            uri = sContentResolver.insert(Tags.CRYPTO_GROUPS_KEYS_URI, groupValue);
            acct.close();
            return symmetricKey;
        }

        int index = acct.getColumnIndex(Tags.DB_FIELD_GROUP_SYMMETRIC_KEY);
        acct.moveToFirst();
        symmetricKey = acct.getString(index);
        acct.close();

        return symmetricKey;
    }

    private String getBlockChainIDFromAddress(String address) {
        if (address.indexOf("@") <= 0) {
            return address;
        }
        return address.substring(0, address.indexOf("@"));
    }

    public boolean getGroupKeyFromServer(String groupAddress) {
        String address = getBlockChainIDFromAddress(groupAddress);
        Account account = getAccount();
        try {
            // replace data by public key
            long unixTime = System.currentTimeMillis() / 1000L;
            String timeString = Long.toString(unixTime);

            PrivateKey privateKey = this.mCryptoManager.getPrivateKey();

            String signedTimeString = this.mCryptoManager.signStrWithPrivateKey(timeString, true);

            String lURL = Tags.BASE_URL + Tags.REQUEST_INVITE_API;

            lURL += Tags.TO_ADDRESS + "=" + account.getAddress().getHex() + "&";
            lURL += Tags.TIME_STAMP + "=" + timeString + "&";
            lURL += Tags.GROUP_ADDRESS + "=" + address + "&";
            lURL += Tags.ENCODED_SIGNATURE + "=" + signedTimeString;

            JSONObject response = sendGetRequestSync(lURL);
            if (response == null) {
                return false;
            }
            System.out.println(response.toString());
            String encryptedGroupKey = response.getString(Tags.GROUP_KEY);
            String groupKey = this.mCryptoManager.decryptStringWithSymmetricKey(getSharedKeyForAllFriends(), encryptedGroupKey);

            updateGroupKey(address, groupKey);

            return true;

        } catch (Exception e) {
            // transactionStr = e.getMessage();
            e.printStackTrace();
        }

        return false;
    }

    private void updateGroupKey(String groupAddress, String groupKey) {
        if (sContentResolver == null) {
            return;
        }
        String address = getBlockChainIDFromAddress(groupAddress);
        // ContentResolver lResolver = new ContentResolver
        final String[] projection = { Tags.DB_FIELD_GROUP_SYMMETRIC_KEY};
        String selection = Tags.DB_FIELD_GROUP_ADDRESS + "='" + address + "'";

        Cursor group = sContentResolver.query(Tags.CRYPTO_GROUPS_KEYS_URI, projection, selection, null, null);

        String symmetricKey = null;
        ContentValues groupValue = new ContentValues(1); // only generate one record

        groupValue.put(Tags.DB_FIELD_GROUP_SYMMETRIC_KEY, groupKey);
        groupValue.put(Tags.DB_FIELD_GROUP_ADDRESS, address);

        if (group.getCount() == 0)
        {
            Uri uri = null;
            uri = sContentResolver.insert(Tags.CRYPTO_GROUPS_KEYS_URI, groupValue);
            group.close();
            return;
        }
        sContentResolver.update(Tags.CRYPTO_GROUPS_KEYS_URI, groupValue, selection, null);
        group.close();
    }

}
