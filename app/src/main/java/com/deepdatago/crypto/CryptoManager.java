package com.deepdatago.crypto;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.io.InputStream;

public interface CryptoManager {
	/**
	 * Generate PrivateKey and Certificate 
	 *
	 * @return      None
	 */	
	// public boolean generateKeyPair();
	
	/**
	 * Generate private key from a RSA PEM file 
	 *
	 * @return      PrivateKey
	 */		
	public PrivateKey getPrivateKey();

	/**
	 * Get public key from a RSA public key PEM file
	 *
	 * @return      PublicKey
	 */		
	public PublicKey getPublicKey();

	/**
	 * Get public key string from a RSA public key PEM file
	 *
	 * @return      PublicKey
	 */
	public String getPublicKeyString();

	/**
	 * Generate public key from a RSA public key PEM string format
	 *
	 * @param  publicKeyStr  public key as String
	 * @return      PublicKey
	 */
	public PublicKey loadPublicKeyFromRSAPEMString(String publicKeyStr);

	/**
	 * Encrypt a byte[] with given public key, and encode it with Base64
	 *
	 * @param  text String that needs to be encrypted
	 * @param  key public key that is used to encrypt the given byte[]
	 * @return      Base64 encoded string of encrypted byte[]
	 */	
    public String encryptStrWithPublicKey(PublicKey key, String text) throws Exception;

	/**
	 * Decrypt a byte[] which is Base64 encoded with given private key
	 *
	 * @param  text Base64 encoded String which needs to be decrypted
	 * @param  key private key that is used to decrypt the given byte[]
	 * @return      Plain text of the encrypted byte[]
	 */	    
    public String decryptStrWithPrivateKey(PrivateKey key, String text) throws Exception;

	/**
	 * Encrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to encrypt the given byte[]
	 * @param  data input string, which needs to be encrypted
	 * @return      Base64 encoded string of the encrypted data
	 */
	public String encryptStringWithSymmetricKey(String inKey, String data);

	/**
	 * Decrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to decrypt the given byte[]
	 * @param  data input string, which needs to be decrypted
	 * @return      Plain text string of the decrypted data
	 */
	public String decryptStringWithSymmetricKey(String inKey, String data);

	/**
	 * Encrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to encrypt the given byte[]
	 * @param  inputFileName input file name, which needs to be encrypted
	 * @param  outputFileName output file name, which needs to be written to
	 * @return      Base64 encoded string of the encrypted data
	 */
	// public void encryptFileWithSymmetricKey(String inKey, String inputFileName, String outputFileName);

	/**
	 * Decrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to decrypt the given byte[]
	 * @param  inputFileName input file name, which needs to be decrypted
	 * @param  outputFileName output file name, which needs to be written to
	 * @return      Plain text string of the decrypted data
	 */
	// public void decryptFileWithSymmetricKey(String inKey, String inputFileName, String outputFileName);


	/**
	 * Encrypt a string with given symmetric key.  Because ChatSessionAdapter.java::sendMediaMessageAsync
	 * uses file input steam
	 *
	 * @param  inKey symmetric key that is used to encrypt the given byte[]
	 * @param  inputStream input stream, which needs to be encrypted
	 * @return      Cipherized input stream
	 */
	public InputStream encryptDataWithSymmetricKey(String inKey, InputStream inputStream);

	/**
	 * Decrypt input stream with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to encrypt the given byte[]
	 * @param  inputStream input stream, which needs to be decrypted
	 * @return      Decrypted input stream
	 */
	public InputStream decryptDataWithSymmetricKey(String inKey, InputStream inputStream);

	/**
	 * Decrypt input stream with given symmetric key
	 *
	 * @param  inString input string to be signed, which needs to be decrypted
	 * @param  urlEncode whether do url encode
	 * @return      base64 encoded signed string
	 */
	public String signStrWithPrivateKey(String inString, boolean urlEncode);

}
