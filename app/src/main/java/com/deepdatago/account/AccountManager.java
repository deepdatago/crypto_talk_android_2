package com.deepdatago.account;

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
     * Generate Register request
     *
     * @param   account: ethereum account
     * @param   dataBytes: transaction data to be signed
     * @return      signed JSON string for transaction
     */
    public String signTransaction(Account account, byte[] dataBytes);

}
