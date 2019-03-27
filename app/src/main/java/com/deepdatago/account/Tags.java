package com.deepdatago.account;

import android.net.Uri;

/**
 * Created by tnnd on 8/28/18.
 */

public class Tags {
    /* API related */
    static public String BASE_SERVER_ADDRESS = "dev.deepdatago.com";
    static public String BASE_URL = "https://" + BASE_SERVER_ADDRESS + "/service/";
    static public String BASE_CONFERENCE_ADDRESS = "conference." + BASE_SERVER_ADDRESS;
    static public String REQUEST_SUMMARY_API = "request/summary/?";
    static public String FRIEND_REQUEST_API = "request/friend/";
    static public String REQUEST_GROUP_INVITE_API = "request/group_invite/";
    static public String REQUEST_INVITE_API = "request/invite/?";
    static public String GET_PUBLIC_KEY_API = "accounts/get_public_key/";
    static public String ACCOUNT_REGISTER_API = "accounts/register/";
    static public String APPROVED_DETAILS_API = "request/approved_details/?";

    /* Database fields */
    static public String DATABASE_NAME = "Crypto";
    static public String ACCOUNT_TABLE_NAME = "account";
    static public String FRIENDS_KEYS_TABLE_NAME = "friends_keys";
    static public String GROUPS_KEYS_TABLE_NAME = "groups_keys";

    static public String DB_FIELD_PRIMARY_ID = "_ID";
    static public String DB_FIELD_SHARED_SYMMETRIC_KEY = "shared_symmetric_key";
    static public String DB_FIELD_PRIVATE_SYMMETRIC_KEY = "private_symmetric_key";
    static public String DB_FIELD_ACCOUNT = "account";
    static public String DB_FIELD_XMPP_USER_NAME = "xmpp_user_name";
    static public String DB_FIELD_XMPP_PASSOWRD = "xmpp_password";
    static public String DB_FIELD_PASSOWRD = "password";
    static public String DB_FIELD_GROUP_ADDRESS = "group_address"; // for GROUPS_KEYS_TABLE_NAME
    static public String DB_FIELD_GROUP_SYMMETRIC_KEY = "group_symmetric_key"; // for GROUPS_KEYS_TABLE_NAME


    /* Content Provider */
    // static public final String PROVIDER_NAME = "com.deepdatago.provider.CryptoProvider";
    // static public final Uri CRYPTO_ACCOUNT_URI = Uri.parse("content://com.deepdatago.provider.Crypto/" + Tags.ACCOUNT_TABLE_NAME);

    static public final String PROVIDER_NAME = "com.deepdatago.provider." + Tags.DATABASE_NAME;
    static public final Uri CRYPTO_ACCOUNT_URI = Uri.parse("content://" + Tags.PROVIDER_NAME + "/" + Tags.ACCOUNT_TABLE_NAME);
    static public final Uri CRYPTO_FRIENDS_KEYS_URI = Uri.parse("content://" + Tags.PROVIDER_NAME + "/" + Tags.FRIENDS_KEYS_TABLE_NAME);
    static public final Uri CRYPTO_GROUPS_KEYS_URI = Uri.parse("content://" + Tags.PROVIDER_NAME + "/" + Tags.GROUPS_KEYS_TABLE_NAME);

    /* JSON requests*/
    static public String TO_ADDRESS = "to_address";
    static public String TIME_STAMP = "time_stamp";
    static public String ENCODED_SIGNATURE = "b64encoded_signature";
    static public String NAME = "name";
    static public String FROM_ADDRESS = "from_address";
    static public String SENDER_ADDRESS = "sender_address";
    static public String REQUEST = "request";
    static public String GROUP_ADDRESS = "group_address";
    static public String GROUP_INVITEE_LIST = "group_invitee_list";
    static public String FRIEND_SYMMETRIC_KEY = "friend_request_symmetric_key";
    static public String ALL_FRIENDS_SYMMETRIC_KEY = "all_friends_symmetric_key";
    static public String TRANSACTION = "transaction";
    static public String PUBLIC_KEY = "publicKey";
    static public String ACTION_TYPE = "action_type";
    static public String GROUP_KEY = "group_key";
    static public String XMPP_ACCOUNT_NUMBER = "xmpp_account_number";
    static public String XMPP_ACCOUNT_PASSWORD = "xmpp_account_password";
    static public String KEYS = "keys";

    /* enum types */
    static public int FriendRequest = 0;
    static public int ApproveRequest = 1;


}
