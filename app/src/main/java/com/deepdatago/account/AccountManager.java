package com.deepdatago.account;

import android.content.ContentResolver;
import org.ethereum.geth.Account;
import org.json.JSONArray;
import org.json.JSONObject;

import android.content.Context;
import java.security.PublicKey;
import java.util.ArrayList;

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
     * @param   contextForHTTP: context to send HTTP request
     * @return      get summary URL
     */
    public JSONArray getSummary(String requestAccount, Context contextForHTTP);

    /**
     * Generate get approved details, the shared symmetric key of fromAccount will be
     * persisted
     *
     * @param   fromAccount: account that has summary info
     * @param   contextForHTTP: context to send HTTP request
     * @return      None
     */
    public void getApprovedDetails(String fromAccount, Context contextForHTTP);

    /**
     * Send or approve friend request, synchronous call
     *
     * @param   toAccount: account that should receive the request
     * @param   requestType: whether it's request friend, or approve friend request
     * @return
     */
    public void friendRequestSync(String toAccount, int requestType);

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
     * get private chat symmetric key for a given friendId
     *
     * @return      Symmetric key for the given friendId
     */
    public String getSymmetricKey(String friendId);

    /**
     * get shared symmetric key for a given friendId
     *
     * @return      shared key for the given friendId
     */
    public String getSharedKey(String friendId);

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

    /**
     * get public key
     *
     * @param   address: address that the public key is requested for
     * @return      public key
     */
    public PublicKey getPublicKey(String address);

    /**
     * create group chat
     *
     * @param   groupAddress: address for the group
     * @return      success or failure
     */
    public boolean createGroupChat(String groupAddress, ArrayList<String> invitees);

    /**
     * get group key
     *
     * @param   groupAddress: address for the group
     * @return      Shared symmetric key for this group
     */
    public String getGroupKey(String groupAddress);

}
