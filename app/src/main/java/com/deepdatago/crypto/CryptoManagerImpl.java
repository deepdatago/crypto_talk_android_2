package com.deepdatago.crypto;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import android.util.Base64;
import java.util.Date;
import java.util.Map;

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
	private final String algorithm; // "RSA"
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
	private final String commonName; // "CN=KeyManagerTest"
	private static CryptoManagerImpl msCryptoManager = null;

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
	public CryptoManagerImpl() {
		this.algorithm = "RSA";
		this.keySize = 4096;
		this.signatureAlg = "SHA256withRSA";
		this.certExpireInDays = 365;
		this.commonName = "CN=KeyManagerTest";
    	Security.addProvider(new BouncyCastleProvider());
    	fixAESKeyLength();
	}

	public static CryptoManager getInstance() {
		if (msCryptoManager == null) {
			synchronized (CryptoManagerImpl.class) {
				if (msCryptoManager == null) {
					msCryptoManager = new CryptoManagerImpl();
				}
			}
		}
		return msCryptoManager;
	}

	public void generateKeyCertificate(String privKeyFileName, String publicKeyFileName, String certFileName) {
    	KeyPair keyPair;
    	PrivateKey privateKey;
    	PublicKey publicKey;
    	
		try {
			keyPair = generateKeyPair(this.algorithm, this.keySize);
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
			writePemFile(privateKey.getEncoded(), this.privateKeyDescription, privKeyFileName);
			writePemFile(publicKey.getEncoded(), this.publicKeyDescription, publicKeyFileName);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return;
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
		
		if (certFileName == null)
			return;
		
    	ContentSigner sigGen;
		try {
			sigGen = new JcaContentSignerBuilder(this.signatureAlg).setProvider(this.providerName).build(privateKey);
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
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
		} catch (CertificateException e) {
			e.printStackTrace();
			return;
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	public PublicKey loadPublicKeyFromRSAPEMString(String publicKeyStr) {
		try {
			String instanceName = "RSA"; // RSA
			KeyFactory factory = KeyFactory.getInstance(instanceName, this.providerName);
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

	public PublicKey loadPublicKeyFromRSAPEM(String fileName) 
		throws FileNotFoundException,
		IOException,
		NoSuchAlgorithmException,
		NoSuchProviderException,
		InvalidKeySpecException
	{
    	String instanceName = "RSA";
    	PEMParser pemParser = null;
    	PemObject pemObject = null;
    	KeyFactory factory = null;
		File privateKeyFile = new File(fileName);
		pemParser = new PEMParser(new FileReader(privateKeyFile));
		pemObject = pemParser.readPemObject();
    	factory = KeyFactory.getInstance(instanceName, this.providerName);
		pemParser.close();

		byte[] content = pemObject.getContent();
	    X509EncodedKeySpec privKeySpec =
	  	      new X509EncodedKeySpec(content);
		
		return factory.generatePublic(privKeySpec);
	}

    
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

    public PrivateKey loadPrivateKeyFromRSAPEM(String fileName) 
    		throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
    	String instanceName = "RSA";
    	PEMParser pemParser = null;
		File privateKeyFile = new File(fileName);
		pemParser = new PEMParser(new FileReader(privateKeyFile));
		PemObject pemObject = pemParser.readPemObject();
    	KeyFactory factory = KeyFactory.getInstance(instanceName, this.providerName);
    	byte[] content = pemObject.getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		pemParser.close();
		try {
			return factory.generatePrivate(privKeySpec);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	   
		return null;
    }   	
    
    public String encryptTextBase64(PublicKey key, byte[] text) throws Exception
    {
        byte[] cipherText = null;
        //
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);

        // iOS cannot decrypt string with "\n"
        return new String(Base64.encode(cipherText, Base64.DEFAULT)).replaceAll("\n", "");
    }    
    
    public String decryptTextBase64(PrivateKey key, byte[] text) throws Exception
    {
    	byte[] decodedBytes = Base64.decode(text, Base64.DEFAULT);
        byte[] dectyptedText = null;
        // decrypt the text using the private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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
	private KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
		keyGen.initialize(keySize);
		return keyGen.genKeyPair();
	}
	
    public static void fixAESKeyLength() {
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength;
        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
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

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        }
        if (newMaxKeyLength < 256)
            throw new RuntimeException(errorString); // hack failed
    }

	public String encryptDataWithSymmetricKey(String inKey, String data) {
		Log.d("CryptoManagerImpl", data);
		SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), "AES");

		Cipher cipher = null;
		try {
			// int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
			// System.out.println("max allowed length: " + maxKeyLen);


			cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
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

	public String decryptDataWithSymmetricKey(String inKey, String data) {
		byte[] decryptedPlainText = null;
		int ptLength = 0;
		Cipher cipher = null;
		SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), "AES");
		try {
			// int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
			// System.out.println("max allowed length: " + maxKeyLen);


			cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
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

		String decryptedString = new String(decryptedPlainText);
		return decryptedString;
	}

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
			SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
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

	public InputStream encryptInputStreamWithSymmetricKey(String inKey, InputStream inputStream) {
		return doCryptoStream(Cipher.ENCRYPT_MODE, inKey, inputStream);
	}

	public InputStream decryptInputStreamWithSymmetricKey(String inKey, InputStream inputStream) {
		return doCryptoStream(Cipher.DECRYPT_MODE, inKey, inputStream);
	}

	public InputStream doCryptoStream(int cipherMode, String inKey, InputStream inputStream) {
		try {
			SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
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
}
