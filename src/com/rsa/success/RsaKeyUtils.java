package com.rsa.success;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.io.pem.PemObject;

public class RsaKeyUtils {
	

	public static final String PEM_PUBLICKEY = "PUBLIC KEY";

	public static final String PEM_PRIVATEKEY = "PRIVATE KEY";

	/**
	 * generateRSAKeyPair
	 * 
	 * @param keySize
	 * @return
	 */
	public static KeyPair generateRSAKeyPair(int keySize) {
		KeyPairGenerator generator = null;
		SecureRandom random = new SecureRandom();
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try {
			generator = KeyPairGenerator.getInstance("RSA", "BC");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}

		generator.initialize(keySize, random);

		KeyPair keyPair = generator.generateKeyPair();

		return keyPair;
	}

	/**
	 * convertToPemKey
	 * 
	 * @param publicKey
	 * @param privateKey
	 * @return
	 */
	public static String convertToPemKey(RSAPublicKey publicKey,
			RSAPrivateKey privateKey) {
		if (publicKey == null && privateKey == null) {
			return null;
		}
		StringWriter stringWriter = new StringWriter();

		try {
			PEMWriter pemWriter = new PEMWriter(stringWriter, "BC");

			if (publicKey != null) {

				pemWriter.writeObject(new PemObject(PEM_PUBLICKEY, publicKey
						.getEncoded()));
			} else {
				pemWriter.writeObject(new PemObject(PEM_PRIVATEKEY, privateKey
						.getEncoded()));
			}
			pemWriter.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return stringWriter.toString();
	}

	public static byte[] sign(String data, byte[] privateKey) throws Exception {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		PrivateKey privateKey2 = keyFactory
				.generatePrivate(pkcs8EncodedKeySpec);
		Signature signature = Signature.getInstance("SHA1WithRSA");
		signature.initSign(privateKey2);
		signature.update(data.getBytes());
		return signature.sign();

	}

	// 后台测试签名的时候 要和前台保持一致，所以需要将结果转换
	public static String bytes2String(byte[] bytes) {
		StringBuilder string = new StringBuilder();
		for (byte b : bytes) {
			String hexString = Integer.toHexString(0x00FF & b);
			string
					.append(hexString.length() == 1 ? "0" + hexString
							: hexString);
		}
		return string.toString();
	}

	public static boolean verify(String data, byte[] publicKey,
			byte[] signatureResult) {
		try {
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
					publicKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey2 = keyFactory
					.generatePublic(x509EncodedKeySpec);

			Signature signature = Signature.getInstance("SHA1WithRSA");
			signature.initVerify(publicKey2);
			signature.update(data.getBytes());

			return signature.verify(signatureResult);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
	

	// 前台的签名结果是将byte 中的一些 负数转换成了正数，
	// 但是后台验证的方法需要的又必须是转换之前的
	public static byte[] hexStringToByteArray(String data) {
		int k = 0;
		byte[] results = new byte[data.length() / 2];
		for (int i = 0; i + 1 < data.length(); i += 2, k++) {
			results[k] = (byte) (Character.digit(data.charAt(i), 16) << 4);
			results[k] += (byte) (Character.digit(data.charAt(i + 1), 16));
		}
		return results;
	}
	
	
	
	/**
	 * 生成公私钥
	 */
	public static KeyPair generatorKeysToDisk() {
		KeyPair k = generateRSAKeyPair(1024);

		String publicKey = convertToPemKey((RSAPublicKey) k.getPublic(), null);
		String privateKey = convertToPemKey(null, (RSAPrivateKey) k
				.getPrivate());

		try {
			IOUtils.write(publicKey, new FileOutputStream(new File("d:/rsa-keys/public")));
			IOUtils.write(privateKey, new FileOutputStream(new File("d:/rsa-keys/private")));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} finally {
			return k;
		}
	}
	
	
	public static RSAPublicKey loadPublicKey() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		FileInputStream fis = null;
		PEMReader reader = null;
		try {
			fis = new FileInputStream(new File("d:/rsa-keys/public"));
			reader = new PEMReader(new InputStreamReader(fis), new PasswordFinder() {  
			    @Override  
			    public char[] getPassword() {  
			        return "".toCharArray();  
			    }  
			});
			//PEMReader pemReader = new PEMReader(sr);
			RSAPublicKey keyPair = (RSAPublicKey) reader.readObject(); 
			return keyPair;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  finally {
			if(reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			if(fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
		}
		return null;
	}
	

	public static void main(String[] args) {
		generatorKeysToDisk();
		System.out.println("over");
	}
	

}
