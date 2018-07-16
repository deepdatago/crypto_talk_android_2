package com.deepdatago.account;

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.BottomNavigationView;
import android.support.v7.app.AppCompatActivity;
import android.view.MenuItem;
import android.widget.TextView;

import com.deepdatago.crypto.CryptoManager;
import com.deepdatago.crypto.CryptoManagerImpl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;

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
import org.json.JSONObject;

/**
 * Created by tnnd on 7/5/18.
 */

public class AccountManagerImpl implements AccountManager {
    private KeyStore mKeyStore = null;
    private String mCreationPassword = null;
    private NodeConfig mNodeConfig = new NodeConfig();
    private Node mNode = null;
    private CryptoManager mCryptoManager = null;
    private String mSymmetricKeyForAllFriends = null; // "63A78349DF7544768E0ECBCF3ACB6527";
    private final String mKeyStoreName = "keystore";
    private java.io.File mFileDir = null;
    private final String mPublicKeyName = "account_rsa_public.pem"; // in mFileDir/keystore
    private final String mPrivateKeyName = "account_rsa_private.pem"; // in mFileDir/keystore
    private final String mPublicServerAddress = "0xce66ae967e95f6f90defa8b58e6ab4a721c3c7fb"; // a server address, can be changed later
    private final String mGethNodeDir = ".eth1";

    public AccountManagerImpl(java.io.File fileDir, String creationPassword, String sharedSymmetricKey) {
        if (fileDir == null || creationPassword == null || sharedSymmetricKey == null)
            return;

        this.mKeyStore = new KeyStore(fileDir + "/" + this.mKeyStoreName, Geth.LightScryptN, Geth.LightScryptP);
        this.mCreationPassword = creationPassword;
        this.mFileDir = fileDir;
        this.mSymmetricKeyForAllFriends = sharedSymmetricKey;

        this.mCryptoManager = new CryptoManagerImpl();

        this.mNodeConfig.setEthereumNetworkID(1);
        BigInt chain = new BigInt(this.mNodeConfig.getEthereumNetworkID());

        try {
            // Node node = Geth.newNode(getFilesDir() + "/keystore", nodeConfig);
            this.mNode = Geth.newNode(fileDir + "/" + this.mGethNodeDir, this.mNodeConfig);
            this.mNode.start();
        } catch (Exception e) {
            // transactionStr = e.getMessage();
            // e.printStackTrace();
            // it is okay that the node is started before
        }

    }
    public Account createAccount() {
        // TODO Load mSymmetricKeyForAllFriends from database
        Account newAccount = null;
        try {
            Accounts accounts = this.mKeyStore.getAccounts();
            if (accounts.size() <= 0) {
                newAccount = this.mKeyStore.newAccount(this.mCreationPassword);
                accounts = this.mKeyStore.getAccounts();
            }
            newAccount = accounts.get(0);

            this.mKeyStore.unlock(newAccount, this.mCreationPassword);


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
            requestNode.put("sender_address", account.getAddress().getHex());

            String encryptedName = this.mCryptoManager.encryptDataWithSymmetricKey(this.mSymmetricKeyForAllFriends, userNickName);
            // String decryptedName = decryptDataWithSymmetricKey(symmetricKeyForAllFriends, encryptedName);
            // System.out.println("decrypted name: " + decryptedName);
            requestNode.put("name", encryptedName);
            requestNode.put("transaction", transactionStr);
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
            // this.mKeyStore.unlock(account, this.mCreationPassword);

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

    private String loadPublicKey() {
        // check if mFileDir + /keystore + keyname exists
        String publicKeyName = this.mFileDir + "/" + this.mKeyStoreName + "/" + this.mPublicKeyName;
        File publicKeyFile = new File(publicKeyName);
        if (! publicKeyFile.exists()) {
            String privateKeyName = this.mFileDir + "/" + this.mKeyStoreName + "/" + this.mPrivateKeyName;
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

}
