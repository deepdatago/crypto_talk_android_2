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
import java.security.Signature;
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

/**
 * Created by tnnd on 7/5/18.
 */

public class AccountManagerImpl implements AccountManager {
    private static ContentResolver sContentResolver = null;
    private static java.io.File sFileDirectory = null;

    private KeyStore mKeyStore = null;
    private String mCreationPassword = null;
    private NodeConfig mNodeConfig = new NodeConfig();
    private Node mNode = null;
    private CryptoManager mCryptoManager = null;
    private String mSymmetricKeyForAllFriends = null; // "63A78349DF7544768E0ECBCF3ACB6527";
    private final String mKeyStoreName = "keystore";
    private final String mPublicKeyName = "account_rsa_public.pem"; // in mFileDir/keystore
    private final String mPrivateKeyName = "account_rsa_private.pem"; // in mFileDir/keystore
    private final String mPublicServerAddress = "0xce66ae967e95f6f90defa8b58e6ab4a721c3c7fb"; // a server address, can be changed later
    private final String mGethNodeDir = ".eth1";
    private final int HTTP_REQUEST_TIMEOUT_IN_SECONDS = 10;
    private static AccountManager msAccountManager = null;

    private AccountManagerImpl() {
        if (sFileDirectory == null || sContentResolver == null)
            return;

        this.mKeyStore = new KeyStore(sFileDirectory + "/" + this.mKeyStoreName, Geth.LightScryptN, Geth.LightScryptP);
        // this.mCreationPassword = creationPassword;
        this.mSymmetricKeyForAllFriends = getSharedAsymmetricKey();

        this.mCryptoManager = new CryptoManagerImpl();

        this.mNodeConfig.setEthereumNetworkID(1);
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

    }

    public static AccountManager getInstance() {
        if (msAccountManager != null) {
            return msAccountManager;
        }
        msAccountManager = new AccountManagerImpl();
        return msAccountManager;
    }

    public static AccountManager getInstance(String password) {
        if (msAccountManager != null) {
            msAccountManager.saveAccountPassword(password);
            return msAccountManager;
        }
        msAccountManager = new AccountManagerImpl();
        msAccountManager.saveAccountPassword(password);
        return msAccountManager;
    }

    public Account createAccount() {
        // TODO Load mSymmetricKeyForAllFriends from database
        Account newAccount = null;
        try {
            Accounts accounts = this.mKeyStore.getAccounts();
            if (accounts.size() <= 0) {
                if (this.mCreationPassword == null) {
                    return null;
                }
                newAccount = this.mKeyStore.newAccount(this.mCreationPassword);
                accounts = this.mKeyStore.getAccounts();
            }
            newAccount = accounts.get(0);

            if (this.mCreationPassword != null) {
                this.mKeyStore.unlock(newAccount, this.mCreationPassword);
            }

            // String addressStr = newAccount.getAddress().getHex();
            // System.out.println("debug acct hex: " + addressStr);
        } catch (Exception e) {
            // e.printStackTrace();
            return null;
        }
        return newAccount;
    }

    public String getRegisterRequest(Account account, String userNickName) {
        String transactionStr = null;
        try {
            // System.out.println("to_address: " + account.getAddress().getHex());

            String data = loadPublicKey();
            // System.out.println("public key: " + data);
            transactionStr = signTransaction(account, data.getBytes("UTF8"));
            // System.out.println("register input length: " + transactionStr.length() + " string: " + transactionStr);
            JSONObject requestNode = new JSONObject();
            requestNode.put(Tags.SENDER_ADDRESS, account.getAddress().getHex());

            String encryptedName = this.mCryptoManager.encryptDataWithSymmetricKey(this.mSymmetricKeyForAllFriends, userNickName);
            // String decryptedName = decryptDataWithSymmetricKey(symmetricKeyForAllFriends, encryptedName);
            // System.out.println("decrypted name: " + decryptedName);
            requestNode.put(Tags.NAME, encryptedName);
            requestNode.put(Tags.TRANSACTION, transactionStr);
            transactionStr = requestNode.toString();
            // System.out.println("register transaction: " + transactionStr);
        } catch (Exception e) {
            transactionStr = e.getMessage();
            e.printStackTrace();

        }
        return transactionStr;
    }

    public String signTransaction(Account account, byte[] dataBytes) {
        long nonce;
        double amount = 0;
        long gasLimit = 0;
        double gasPrice = 0;
        BigInt chain = new BigInt(this.mNodeConfig.getEthereumNetworkID());
        String returnStr = null;

        try {
            String accountPassword = getAccountPassword();
            if (accountPassword == null) {
                return null;
            }
            this.mKeyStore.unlock(account, accountPassword);

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

        return returnStr;
    }

    public JSONArray getFriendRequest(String requestAccount, android.content.Context contextForHTTP) {

        long unixTime = System.currentTimeMillis() / 1000L;
        String timeString = Long.toString(unixTime);

        String transactionStr = b64EncryptedSignedBytes(timeString.getBytes());
        if (transactionStr == null || transactionStr.length() == 0) {
            return null;
        }

        String lURL = Tags.BASE_URL + Tags.REQUEST_SUMMARY_API;

        lURL += Tags.TO_ADDRESS + "=" + requestAccount + "&";
        lURL += Tags.TIME_STAMP + "=" + timeString + "&";
        lURL += Tags.ENCODED_SIGNATURE + "=" + transactionStr;

        RequestFuture<JSONObject> requestFuture=RequestFuture.newFuture();
        JsonObjectRequest request = new JsonObjectRequest(Request.Method.GET,
                lURL,new JSONObject(),requestFuture,requestFuture);
        RequestQueue queue = Volley.newRequestQueue(contextForHTTP);
        queue.add(request);

        JSONObject responseObject = sendGetRequestSync(lURL, contextForHTTP);
        if (responseObject == null) {
            return null;
        }
        JSONArray returnArray = new JSONArray();
        try {
            JSONArray friendReqArray = responseObject.getJSONArray("friend_request");
            PrivateKey privateKey = this.mCryptoManager.loadPrivateKeyFromRSAPEM(getPrivateKeyFileName());

            for (int i = 0; i < friendReqArray.length(); i++) {
                JSONObject object = friendReqArray.getJSONObject(i);
                String name = object.getString(Tags.NAME);
                String fromAddress = object.getString(Tags.FROM_ADDRESS).replace("0x", "");
                String requestStr = object.getString(Tags.REQUEST);
                requestStr = requestStr.replace("\\\"", "\"");
                JSONObject keyObject = new JSONObject(requestStr);
                String friendAESKey = keyObject.getString(Tags.FRIEND_SYMMETRIC_KEY);
                String allFriendsAESKey = keyObject.getString(Tags.ALL_FRIENDS_SYMMETRIC_KEY);
                allFriendsAESKey = this.mCryptoManager.decryptTextBase64(privateKey, allFriendsAESKey.getBytes());
                friendAESKey = this.mCryptoManager.decryptTextBase64(privateKey, friendAESKey.getBytes());
                name = this.mCryptoManager.decryptDataWithSymmetricKey(allFriendsAESKey, name);

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

    private JSONObject sendGetRequestSync(String iURL, android.content.Context contextForHTTP) {
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
        return null;
    }

    private String getPrivateKeyFileName() {
        String privateKeyName = sFileDirectory + "/" + this.mKeyStoreName + "/" + this.mPrivateKeyName;
        return privateKeyName;
    }

    private String loadPublicKey() {
        // check if mFileDir + /keystore + keyname exists
        String publicKeyName = sFileDirectory + "/" + this.mKeyStoreName + "/" + this.mPublicKeyName;
        File publicKeyFile = new File(publicKeyName);
        if (! publicKeyFile.exists()) {
            String privateKeyName = sFileDirectory + "/" + this.mKeyStoreName + "/" + this.mPrivateKeyName;
            this.mCryptoManager.generateKeyCertificate(privateKeyName, publicKeyName, null);
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

    public String getSharedAsymmetricKey()
    {
        if (sContentResolver == null) {
            return null;
        }
        // ContentResolver lResolver = new ContentResolver

        Cursor acct = sContentResolver.query(Tags.CRYPTO_ACCOUNT_URI, null, "_ID=1", null, null);

        String symmetricKey = null;
        if (acct.getCount() == 0)
        {
            ContentValues accountValue = new ContentValues(1);
            // contactListValues.put(Imps.ContactList.NAME, list.getName());
            UUID idOne = UUID.randomUUID();
            symmetricKey = idOne.toString().replace("-", "");

            accountValue.put(CryptoProvider.SHARED_SYMMETRIC_KEY, symmetricKey);

            Uri uri = null;
            uri = sContentResolver.insert(Tags.CRYPTO_ACCOUNT_URI, accountValue);
            return symmetricKey;
        }

        int index = acct.getColumnIndex("shared_symmetric_key");
        acct.moveToFirst();
        symmetricKey = acct.getString(index);

        return symmetricKey;
    }

    public static void initStaticMembers(ContentResolver iContentResolver, java.io.File iFileDirectory) {
        if (sContentResolver != null || sFileDirectory != null) {
            return;
        }
        sContentResolver = iContentResolver;
        sFileDirectory = iFileDirectory;
        AccountManagerImpl.getInstance();
    }

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
            return password;

        }
        return null;
    }

    private String b64EncryptedSignedBytes(byte[] inputBytes)
    {
        String transactionStr = null;
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            PrivateKey privateKey = this.mCryptoManager.loadPrivateKeyFromRSAPEM(getPrivateKeyFileName());

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
        final String selection = "lower(" + Tags.DB_FIELD_ACCOUNT + ")='" + account.toLowerCase() + "'";
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
            }
        }

        return null;
    }

}
