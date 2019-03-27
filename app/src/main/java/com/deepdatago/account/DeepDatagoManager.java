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

public interface DeepDatagoManager {
    /**
     * Generate Register request
     *
     * @param   password: ethereum account password
     * @param   userNickName: user name that wants to be displayed to friends.  This name will be encrypted so server does not know
     * @return      RegisterRequest JSON string
     */
    public String registerRequest(String password, String userNickName);


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
     * @param   password: ethereum account password to sign transaction
     * @param   dataBytes: transaction data to be signed
     * @return      signed JSON string for transaction
     */
    public String signTransaction(Account account, String password, byte[] dataBytes);

    /**
     * generate shared key for all friends
     *
     * @return      Shared symmetric key for all friends
     */
    public String getSharedKeyForAllFriends();

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
    public String getAllFriendsKey(String friendId);


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

    /**
     * get group key from server, persist it into database
     *
     * @param   groupAddress: address for the group
     * @return      boolean value indicate success or failure
     */
    public boolean getGroupKeyFromServer(String groupAddress);

}
