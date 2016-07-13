
package com.rsa.ali;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

public class RSA{
	
	public static final String  SIGN_ALGORITHMS = "SHA1WithRSA";
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
		Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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
	
	
	/**
	* RSA签名
	* @param content 待签名数据
	* @param privateKey 商户私钥
	* @param input_charset 编码格式
	* @return 签名值
	*/
	public static String sign(String content, String privateKey, String input_charset)
	{
        try 
        {
        	PKCS8EncodedKeySpec priPKCS8 	= new PKCS8EncodedKeySpec( Base64.decode(privateKey) ); 
        	KeyFactory keyf 				= KeyFactory.getInstance("RSA");
        	PrivateKey priKey 				= keyf.generatePrivate(priPKCS8);

            java.security.Signature signature = java.security.Signature
                .getInstance(SIGN_ALGORITHMS);

            signature.initSign(priKey);
            signature.update( content.getBytes(input_charset) );

            byte[] signed = signature.sign();
            
            return Base64.encode(signed);
        }
        catch (Exception e) 
        {
        	e.printStackTrace();
        }
        
        return null;
    }
	
	/**
	* RSA验签名检查
	* @param content 待签名数据
	* @param sign 签名值
	* @param ali_public_key 支付宝公钥
	* @param input_charset 编码格式
	* @return 布尔值
	*/
	public static boolean verify(String content, String sign, String ali_public_key, String input_charset)
	{
		try 
		{
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        byte[] encodedKey = Base64.decode(ali_public_key);
	        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));

		
			java.security.Signature signature = java.security.Signature
			.getInstance(SIGN_ALGORITHMS);
		
			signature.initVerify(pubKey);
			signature.update( content.getBytes(input_charset) );
		
			boolean bverify = signature.verify( Base64.decode(sign) );
			return bverify;
			
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	* 解密
	* @param content 密文
	* @param private_key 商户私钥
	* @param input_charset 编码格式
	* @return 解密后的字符串
	*/
	public static String decrypt(String content, String private_key, String input_charset) throws Exception {
        PrivateKey prikey = getPrivateKey(private_key);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, prikey);

        InputStream ins = new ByteArrayInputStream(Base64.decode(content));
        ByteArrayOutputStream writer = new ByteArrayOutputStream();
        //rsa解密的字节大小最多是128，将需要解密的内容，按128位拆开解密
        byte[] buf = new byte[128];
        int bufl;

        while ((bufl = ins.read(buf)) != -1) {
            byte[] block = null;

            if (buf.length == bufl) {
                block = buf;
            } else {
                block = new byte[bufl];
                for (int i = 0; i < bufl; i++) {
                    block[i] = buf[i];
                }
            }

            writer.write(cipher.doFinal(block));
        }

        return new String(writer.toByteArray(), input_charset);
    }

	
	/**
	* 得到私钥
	* @param key 密钥字符串（经过base64编码）
	* @throws Exception
	*/
	public static PrivateKey getPrivateKey(String key) throws Exception {

		byte[] keyBytes;
		
		keyBytes = Base64.decode(key);
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		
		return privateKey;
	}
	
	/**
	 * 生成公钥/私钥
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> getKeyMap() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);
        SecureRandom secrand = new SecureRandom();
 	   	//secrand.setSeed("daris".getBytes()); // 初始化随机产生器
 	   	//keyPairGen.initialize(1024, secrand);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put("PUK", publicKey);
        keyMap.put("PRK", privateKey);
        return keyMap;
	}
}
