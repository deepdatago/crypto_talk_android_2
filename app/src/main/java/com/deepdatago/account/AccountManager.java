package com.deepdatago.account;

import android.content.ContentResolver;
import org.ethereum.geth.Account;
import org.json.JSONArray;
import org.json.JSONObject;

import android.content.Context;

/**
 * Created by tnnd on 7/5/18.
 */

public interface AccountManager {
    /**
     * Generate PrivateKey and Certificate
     *
     * @param
     * @return      org.ethereum.geth.Account
     */
    public Account createAccount();

    /**
     * Generate Register request
     *
     * @param   account: ethereum account
     * @param   userNickName: user name that wants to be displayed to friends.  This name will be encrypted so server does not know
     * @return      RegisterRequest JSON string
     */
    public String getRegisterRequest(Account account, String userNickName);


    /**
     * Generate get summary request
     *
     * @param   requestAccount: account that has summary info
     * @return      get summary URL
     */
    public JSONArray getFriendRequest(String requestAccount, Context contextForHTTP);

    /**
     * Generate signed transaction
     *
     * @param   account: ethereum account
     * @param   dataBytes: transaction data to be signed
     * @return      signed JSON string for transaction
     */
    public String signTransaction(Account account, byte[] dataBytes);

    /**
     * generate shared key for all friends
     *
     * @return      Shared assymmetric key for all friends
     */
    public String getSharedAsymmetricKey();

    /**
     * Save account password
     *
     * @param   password: for account
     * @return      Shared assymmetric key for all friends
     */
    public void saveAccountPassword(String password);

    /**
     * Get keys by its account address
     *
     * @param   account: account name for the friend/contact
     * @return      JSON object that has all keys info
     */
    public JSONObject getFriendKeys(String account);

}
