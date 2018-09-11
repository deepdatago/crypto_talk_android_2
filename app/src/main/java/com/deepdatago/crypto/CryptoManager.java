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
	 * @param  privKeyFileName  output file name of private key 
	 * @param  publicKeyFileName  output file name of public key 
	 * @param  certFileName output file name of certificate, could be null
	 * @return      None
	 */	
	public void generateKeyCertificate(String privKeyFileName, String publicKeyFileName, String certFileName);
	
	/**
	 * Generate public key from a RSA X.509 certificate file 
	 *
	 * @param  certFileName input file name of certificate
	 * @return      PublicKey
	 */	
	public PublicKey loadPublicKeyFromRSA_X509_CertificatePEM(String certFileName) 
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException;

	/**
	 * Generate private key from a RSA PEM file 
	 *
	 * @param  privateKeyFileName input file name of private key
	 * @return      PrivateKey
	 */		
	public PrivateKey loadPrivateKeyFromRSAPEM(String privateKeyFileName) 
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException;
	
	/**
	 * Generate public key from a RSA public key PEM file
	 *
	 * @param  fileName  input file name of a public key 
	 * @return      PublicKey
	 */		
	public PublicKey loadPublicKeyFromRSAPEM(String fileName) throws
		FileNotFoundException,
		IOException,
		NoSuchAlgorithmException,
		NoSuchProviderException,
		InvalidKeySpecException;

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
	 * @param  text input byte[] from text that needs to be encrypted
	 * @param  key public key that is used to encrypt the given byte[]
	 * @return      Base64 encoded string of encrypted byte[]
	 */	
    public String encryptTextBase64(PublicKey key, byte[] text) throws Exception;

	/**
	 * Decrypt a byte[] which is Base64 encoded with given private key
	 *
	 * @param  text input byte[] that is Base64 encoded, which needs to be decrypted
	 * @param  key private key that is used to decrypt the given byte[]
	 * @return      Plain text of the encrypted byte[]
	 */	    
    public String decryptTextBase64(PrivateKey key, byte[] text) throws Exception;

	/**
	 * Encrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to encrypt the given byte[]
	 * @param  data input string, which needs to be encrypted
	 * @return      Base64 encoded string of the encrypted data
	 */
	public String encryptDataWithSymmetricKey(String inKey, String data);

	/**
	 * Decrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to decrypt the given byte[]
	 * @param  data input string, which needs to be decrypted
	 * @return      Plain text string of the decrypted data
	 */
	public String decryptDataWithSymmetricKey(String inKey, String data);

	/**
	 * Encrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to encrypt the given byte[]
	 * @param  inputFileName input file name, which needs to be encrypted
	 * @param  outputFileName output file name, which needs to be written to
	 * @return      Base64 encoded string of the encrypted data
	 */
	public void encryptFileWithSymmetricKey(String inKey, String inputFileName, String outputFileName);

	/**
	 * Decrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to decrypt the given byte[]
	 * @param  inputFileName input file name, which needs to be decrypted
	 * @param  outputFileName output file name, which needs to be written to
	 * @return      Plain text string of the decrypted data
	 */
	public void decryptFileWithSymmetricKey(String inKey, String inputFileName, String outputFileName);


	/**
	 * Encrypt a string with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to encrypt the given byte[]
	 * @param  inputStream input stream, which needs to be encrypted
	 * @return      Cipherized input stream
	 */
	public InputStream encryptInputStreamWithSymmetricKey(String inKey, InputStream inputStream);

	/**
	 * Decrypt input stream with given symmetric key
	 *
	 * @param  inKey symmetric key that is used to encrypt the given byte[]
	 * @param  inputStream input stream, which needs to be decrypted
	 * @return      Decrypted input stream
	 */
	public InputStream decryptInputStreamWithSymmetricKey(String inKey, InputStream inputStream);

}
