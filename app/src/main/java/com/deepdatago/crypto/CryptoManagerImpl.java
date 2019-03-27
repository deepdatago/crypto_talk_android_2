package com.deepdatago.crypto;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import android.content.ContentResolver;
import android.util.Base64;
import java.util.Date;
import java.util.Map;
import java.net.URLEncoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
// import javax.crypto.spec.SecretKeySpec.PKCS;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import android.util.Log;

public class CryptoManagerImpl implements CryptoManager {
	private final String algorithm;
	private final int keySize; // 4096
	private final int certExpireInDays; // 365
	private final String signatureAlg; // signatureAlgorithm "SHA256withRSA"

	// in order to work with iOS version of this chat App, the description cannot be changed to something else
	// otherwise, iOS counter part will not be able to encrypt the data with the public key
	// OTRKit/CryptoManager/CryptoManager.swift::encryptStrWithPublicKey
	private final String privateKeyDescription = "PRIVATE KEY";
	private final String publicKeyDescription = "PUBLIC KEY";
	private final String certificateDescription = "CERTIFICATE";

	private final String providerName = "BC"; // for bouncy castle
	private static final String cryptoAlgorithmAES = "AES"; // for bouncy castle
	private final String cipherAsymmetricTransformation = "RSA/ECB/PKCS1Padding";
	private final String ciphersSymmetricTransformation = "AES/ECB/PKCS7Padding";
	private final String commonName; // "CN=KeyManagerTest"
	private static CryptoManagerImpl msCryptoManager = null;
	private static java.io.File sFileDirectory = null;
	private final String mKeyStoreName = "keystore";
	private final String mPublicKeyName = "account_rsa_public.pem"; // in mFileDir/keystore
	private final String mPrivateKeyName = "account_rsa_private.pem"; // in mFileDir/keystore

	private PublicKey mPublicKey = null;
	private PrivateKey mPrivateKey = null;

	/*
	public CryptoManagerImpl(String algorithm,
			String signatureAlg, 
			int keySize, 
			int certExpireInDays, 
			String commonName) {
		this.algorithm = algorithm;
		this.keySize = keySize;
		this.signatureAlg = signatureAlg;
		this.certExpireInDays = certExpireInDays;
		this.commonName = commonName;
    	Security.addProvider(new BouncyCastleProvider());
    	fixAESKeyLength();
	}
	*/
	public CryptoManagerImpl() {
		this.algorithm = "RSA";
		this.keySize = 4096;
		this.signatureAlg = "SHA256withRSA";
		this.certExpireInDays = 365;
		this.commonName = "CN=KeyManagerTest";
    	Security.addProvider(new BouncyCastleProvider());
    	fixAESKeyLength();

		// initialize keys
    	generateKeyPair();
    	this.mPublicKey = loadPublicKey();
    	this.mPrivateKey = loadPrivateKey();
	}

	public static CryptoManager getInstance() {
		if (CryptoManagerImpl.sFileDirectory == null) {
			return null;
		}
		if (msCryptoManager == null) {
			synchronized (CryptoManagerImpl.class) {
				if (msCryptoManager == null) {
					msCryptoManager = new CryptoManagerImpl();
				}
			}
		}
		return msCryptoManager;
	}

	private boolean generateKeyPair() {
		if (getPublicKeyString() != null) {
			// no need to re-generate keypair
			return false;
		}
    	String privKeyFileName = getPrivateKeyFileName();
    	String publicKeyFileName = getPublicKeyFileName();
    	// String certFileName = null;

		KeyPair keyPair;
    	PrivateKey privateKey;
    	PublicKey publicKey;
    	
		try {
			keyPair = generate(this.algorithm, this.keySize);
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
			// getKeyStoreDir();
			File keyStoreFolder = new File(getKeyStoreDir());
			if (!keyStoreFolder.exists()) {
				keyStoreFolder.mkdirs();
			}
			writePemFile(privateKey.getEncoded(), this.privateKeyDescription, privKeyFileName);
			writePemFile(publicKey.getEncoded(), this.publicKeyDescription, publicKeyFileName);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;

		/* for future use
		if (certFileName == null)
			return true; // certFile is optional to generate
		
    	ContentSigner sigGen;
		try {
			sigGen = new JcaContentSignerBuilder(this.signatureAlg).setProvider(this.providerName).build(privateKey);
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

    	SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    	 
    	Date startDate = new Date(System.currentTimeMillis());
    	Date endDate = new Date(System.currentTimeMillis() + this.certExpireInDays * 24 * 60 * 60 * 1000);
    	 
    	X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(
    	          new X500Name(this.commonName),
    	          BigInteger.ONE,
    	          startDate, endDate,
    	          new X500Name(this.commonName),
    	          subPubKeyInfo);
    	     
    	X509CertificateHolder certHolder = v1CertGen.build(sigGen); 
    	X509Certificate certificate;
		try {
			certificate = new JcaX509CertificateConverter().setProvider(this.providerName)
				  .getCertificate( certHolder );
	    	writePemFile(certificate.getEncoded(), this.certificateDescription, certFileName);
	    	return true;
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
		*/
	}

	public PublicKey loadPublicKeyFromRSAPEMString(String publicKeyStr) {
		try {
			KeyFactory factory = KeyFactory.getInstance(this.algorithm, this.providerName);
			byte[] keyBytes = Base64.decode(publicKeyStr, Base64.DEFAULT);
			/*
			String tmpStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhduH6p/KZcbvgCmJPsaS\n" +
					"/xt4uPQtlnIP1MnSGpKkFTwC5bLKfNpTYm8NAgjoOsdlNgVK+KJUzyewkkS17Oo0\n" +
					"5QejUatkH+neIdymWEJsWmFK1JgaBy+tVquPj9IhqMtQv3njGllEHU1Sk9X6TRRS\n" +
					"a2HrdNAX1fX1PKvt4V5EMVULiGEptM0A7JvI+GX4IdWhh63irAqlTQIqY2zPjlhg\n" +
					"5mM6qOmtZSGnwc/Q8hAmZ0OTbmR1vSr/ow8t20jmEAsTMbdIPpg+kXaS+skxkR5V\n" +
					"QeY7dCQyrnqLqJawZadFqzClHbMVNPV44q3EV0nwamjkGEpwaZzWs3sGsKSi5AET\n" +
					"bQIDAQAB";
			keyBytes = Base64.decode(tmpStr, Base64.DEFAULT);
			*/

			X509EncodedKeySpec privKeySpec =
					new X509EncodedKeySpec(keyBytes);

			PublicKey publicKey = factory.generatePublic(privKeySpec);

			return publicKey;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public PublicKey getPublicKey() {
		return mPublicKey;
	}

	private PublicKey loadPublicKey()
	{
    	PEMParser pemParser = null;
    	PemObject pemObject = null;
    	KeyFactory factory = null;
    	try {
			File privateKeyFile = new File(getPublicKeyFileName());
			pemParser = new PEMParser(new FileReader(privateKeyFile));
			pemObject = pemParser.readPemObject();
			factory = KeyFactory.getInstance(this.algorithm, this.providerName);
			pemParser.close();

			byte[] content = pemObject.getContent();
			X509EncodedKeySpec privKeySpec =
					new X509EncodedKeySpec(content);

			return factory.generatePublic(privKeySpec);
		}
		catch (Exception e) {
			/*
		throws FileNotFoundException,
		IOException,
		NoSuchAlgorithmException,
		NoSuchProviderException,
		InvalidKeySpecException
		*/
			e.printStackTrace();
		}
		return null;
	}

	/*
	public PublicKey loadPublicKeyFromRSA_X509_CertificatePEM(String fileName)
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
    	X509Certificate certificate = null;
    	String instanceName = "X.509";

    	try {
        	CertificateFactory certFactory = null;
			certFactory= CertificateFactory
					  .getInstance(instanceName, this.providerName);
			certificate = (X509Certificate) certFactory
					  .generateCertificate(new FileInputStream(fileName));
			
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
    	
    	return certificate.getPublicKey();
    }
    */

	public PrivateKey getPrivateKey () {
		return this.mPrivateKey;
	}

    private PrivateKey loadPrivateKey() {
    	PEMParser pemParser = null;
    	try {
			File privateKeyFile = new File(getPrivateKeyFileName());
			pemParser = new PEMParser(new FileReader(privateKeyFile));
			PemObject pemObject = pemParser.readPemObject();
			KeyFactory factory = KeyFactory.getInstance(this.algorithm, this.providerName);
			byte[] content = pemObject.getContent();
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
			pemParser.close();
			return factory.generatePrivate(privKeySpec);
		}
		catch (Exception e) {
			// throws IOException,
			// NoSuchProviderException,
			// NoSuchAlgorithmException
			e.printStackTrace();
		}
		return null;
    }   	
    
    public String encryptStrWithPublicKey(PublicKey key, String text) throws Exception
    {
        byte[] cipherText = null;
        //
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance(this.cipherAsymmetricTransformation);

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text.getBytes());

        // iOS cannot decrypt string with "\n"
        return new String(Base64.encode(cipherText, Base64.DEFAULT)).replaceAll("\n", "");
    }    
    
    public String decryptStrWithPrivateKey(PrivateKey key, String text) throws Exception
    {
    	byte[] decodedBytes = Base64.decode(text.getBytes(), Base64.DEFAULT);
        byte[] dectyptedText = null;
        // decrypt the text using the private key
        Cipher cipher = Cipher.getInstance(this.cipherAsymmetricTransformation);
        cipher.init(Cipher.DECRYPT_MODE, key);
        dectyptedText = cipher.doFinal(decodedBytes);
        return new String(dectyptedText);
    }
    
    private void writePemFile(byte[] encodedBytes, String description, String filename) throws IOException {
    	PemObject pemObject = new PemObject(description, encodedBytes);
		PemWriter pemWriter = null;
		pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
		pemWriter.writeObject(pemObject);
		pemWriter.close();
	}
	private KeyPair generate(String algorithm, int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
		keyGen.initialize(keySize);
		return keyGen.genKeyPair();
	}
	
    public static void fixAESKeyLength() {
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength;
        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength(CryptoManagerImpl.cryptoAlgorithmAES)) < 256) {
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor(null);
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance(null);
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor(null);
                con.setAccessible(true);
                Object allPermissions = con.newInstance(null);
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength(CryptoManagerImpl.cryptoAlgorithmAES);
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        }
        if (newMaxKeyLength < 256)
            throw new RuntimeException(errorString); // hack failed
    }

	public String encryptStringWithSymmetricKey(String inKey, String data) {
		Log.d("CryptoManagerImpl", data);
		SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), CryptoManagerImpl.cryptoAlgorithmAES);

		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(this.ciphersSymmetricTransformation, this.providerName);
			cipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		byte[] cipherText = null;
		int ctLength = 0;

		try {
			cipherText = cipher.doFinal(data.getBytes(Charset.forName("UTF-8")));
		} catch (BadPaddingException e)
		{
			e.printStackTrace();

		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String encodedEncryptedStr = new String(Base64.encode(cipherText, Base64.DEFAULT));
		encodedEncryptedStr = encodedEncryptedStr.replace("\n", "");
		Log.d("encrypted", encodedEncryptedStr);
		return encodedEncryptedStr;
	}

	public String decryptStringWithSymmetricKey(String inKey, String data) {
		byte[] decryptedPlainText = null;
		int ptLength = 0;
		Cipher cipher = null;
		if (inKey.length() == 0 || data.length() == 0) {
			return "";
		}
		SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), CryptoManagerImpl.cryptoAlgorithmAES);
		try {
			cipher = Cipher.getInstance(this.ciphersSymmetricTransformation, this.providerName);
			cipher.init(Cipher.DECRYPT_MODE, key);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			decryptedPlainText = cipher.doFinal(Base64.decode(data, Base64.DEFAULT));
		} catch (BadPaddingException e)
		{
			e.printStackTrace();

		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		if (decryptedPlainText == null) {
			return "";
		}

		String decryptedString = new String(decryptedPlainText);
		return decryptedString;
	}
	/*
	public void encryptFileWithSymmetricKey(String inKey, String inputFileName, String outputFileName) {
		try {
			File inputFile = new File(inputFileName);
			File outputFile = new File(outputFileName);
			doCrypto(Cipher.ENCRYPT_MODE, inKey, inputFile, outputFile);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void decryptFileWithSymmetricKey(String inKey, String inputFileName, String outputFileName) {
		try {
			File inputFile = new File(inputFileName);
			File outputFile = new File(outputFileName);
			doCrypto(Cipher.DECRYPT_MODE, inKey, inputFile, outputFile);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void doCrypto(int cipherMode, String inKey, File inputFile,
						  File outputFile) throws Exception {
		try {
			SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), CryptoManagerImpl.cryptoAlgorithmAES);
			Cipher cipher = Cipher.getInstance(this.ciphersSymmetricTransformation, this.providerName);
			cipher.init(cipherMode, key);

			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);

			byte[] outputBytes = cipher.doFinal(inputBytes);

			FileOutputStream outputStream = new FileOutputStream(outputFile);
			outputStream.write(outputBytes);

			inputStream.close();
			outputStream.close();

		} catch (Exception e) {
			throw e;
		}
	}
	*/

	public InputStream encryptDataWithSymmetricKey(String inKey, InputStream inputStream) {
		return doCryptoStream(Cipher.ENCRYPT_MODE, inKey, inputStream);
	}

	public InputStream decryptDataWithSymmetricKey(String inKey, InputStream inputStream) {
		return doCryptoStream(Cipher.DECRYPT_MODE, inKey, inputStream);
	}

	public InputStream doCryptoStream(int cipherMode, String inKey, InputStream inputStream) {
		try {
			SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), CryptoManagerImpl.cryptoAlgorithmAES);
			Cipher cipher = Cipher.getInstance(this.ciphersSymmetricTransformation, this.providerName);
			cipher.init(cipherMode, key);

			// FileInputStream inputStream = new FileInputStream(inputFile);
			int inputLength = inputStream.available();
			byte[] inputBytes = new byte[inputLength];
			inputStream.read(inputBytes);

			byte[] outputBytes = cipher.doFinal(inputBytes);

			// FileOutputStream outputStream = new FileOutputStream(outputFile);
			// outputStream.write(outputBytes);
			InputStream cipherInputStream = new ByteArrayInputStream(outputBytes);

			// inputStream.close();
			// outputStream.close();
			return cipherInputStream;

		} catch (Exception e) {
			e.printStackTrace();;
		}
		return null;
	}

	public String signStrWithPrivateKey(String inString, boolean urlEncode) {
		try {
			byte[] data = inString.getBytes();
			Signature sig = Signature.getInstance(this.signatureAlg);
			sig.initSign(getPrivateKey());
			sig.update(data);
			byte[] signatureBytes = sig.sign();
			String signatureStr = new String(Base64.encode(signatureBytes, Base64.DEFAULT));
			if (urlEncode) {
				return URLEncoder.encode(signatureStr, "UTF-8");
			}
			return signatureStr;
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void initStaticMembers(java.io.File iFileDirectory) {
		if (sFileDirectory != null) {
			return;
		}
		sFileDirectory = iFileDirectory;
		CryptoManagerImpl.getInstance();
	}

	private String getKeyStoreDir() {
		return sFileDirectory + "/" + this.mKeyStoreName;
	}
	private String getPrivateKeyFileName() {
		String privateKeyName = getKeyStoreDir() + "/" + this.mPrivateKeyName;
		return privateKeyName;
	}

	private String getPublicKeyFileName() {
		String publicKeyName = getKeyStoreDir() + "/" + this.mPublicKeyName;
		return publicKeyName;
	}

	private String getStringFromFile (String filePath) {
		File fl = new File(filePath);
		FileInputStream fin = null;
		try {
			fin = new FileInputStream(fl);

			BufferedReader reader = new BufferedReader(new InputStreamReader(fin));
			StringBuilder sb = new StringBuilder();
			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append("\n");
			}
			reader.close();
			String ret = sb.toString();
			//Make sure you close all streams.
			// fin.close();
			return ret;
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			try {
				fin.close();
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	// This function is only used once in this app, so, do not need to keep pubilc key string in memory
	public String getPublicKeyString() {
		File publicKeyFile = new File(getPublicKeyFileName());
		if (! publicKeyFile.exists()) {
			return null;
		}
		String publicKeyContent = null;
		try {
			publicKeyContent = getStringFromFile(getPublicKeyFileName());
			return publicKeyContent;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
