package com.rsa.encrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.Key;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

public class TestEncrypt {

	private String publicKey;
	private String privateKey;

	@Before
	public void setUp() throws Exception {
		Map<String, Key> keyMap = RSACoder.initKey();
		publicKey = RSACoder.getPublicKey(keyMap);
		privateKey = RSACoder.getPrivateKey(keyMap);
		System.err.println("公钥: \n\r" + publicKey);
		System.err.println("私钥： \n\r" + privateKey);
	}

	@Test
	public void test() throws Exception {
		System.err.println("公钥加密——私钥解密");
		String inputStr = "我是中国人我是中国人我是中国人";
		byte[] encodedData = RSACoder.encryptByPublicKey(inputStr, publicKey);
		System.out.println(encodedData);
		byte[] decodedData = RSACoder.decryptByPrivateKey(encodedData, privateKey);
		String outputStr = new String(decodedData);
		System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);
	}

	@Test
	public void testSign() throws Exception {
		System.err.println("私钥加密——公钥解密");
		String inputStr = "sign";
		byte[] data = inputStr.getBytes();
		byte[] encodedData = RSACoder.encryptByPrivateKey(data, privateKey);
		byte[] decodedData = RSACoder.decryptByPublicKey(encodedData, publicKey);
		String outputStr = new String(decodedData);
		System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);
		System.err.println("私钥签名——公钥验证签名");
		// 产生签名
		String sign = RSACoder.sign(encodedData, privateKey);
		System.err.println("签名:" + sign);
		// 验证签名
		boolean status = RSACoder.verify(encodedData, publicKey, sign);
		System.err.println("状态:" + status);
		assertTrue(status);
	}
	
	
	@Test
	public void testDecryptJsParams() throws Exception {
		String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJAKkFu7064y16qokEgRugraC4mYufXw140Z652b7deH0nvPZURc8uGLaCKopbP7LcIrV0SMycuoNN5vdg4uvP9l59HfC2a60stx876o+79o5t5IZ59md0KyE384DE/G28Y5rLdVWqgr3Ddxl/KEhCDj+Q2m5+l9pqlIOm+/gK2vAgMBAAECgYEAjNtHv+01W6wsap7cOR3cqLABiFTpxS/4Geu3FTFerN4NXzW4+dlLSnRhKUNyh0ahwLdRZ5+l1ppu2PZ2o/fgqQNp6JKHdLhutmP1zT2qOhr+G0Y5UXQJBhEKb3GsiEuyXECfV9J+A1kCYi2BIXERU1OBPFcsAE/BNdJuzaRiXoECQQDkaLLyPRVKLWRcUBseAeBaJCcAYtSVE+HbZfv+eaFtb4lkvjwMhUb28AhDP1TNyQbx3AiefAsC8ywklx8GlIEpAkEAoXDiahsEAsymQEB5cWGiMUW19C38Iv58DpEiOMpG17wIOF1NrQY/yNsz8WSKNjl4Ux0du7m3UXCVH6gsHrPbFwJAO3NM8GQZwH7kGmr3Q+41GQFD7YPL1Smhpdt7pZa+/58CYehp9NBT0j5TyD0Zs55ZYmZlD+s1aoUkvjlfZ/ULUQJAa1phdSVZ2XK06uz01MyTyigNAr7Bd5O6cwVXuGPqD/Ndk/2XdYM+TxZUyCSPM9erh7lI2Fh66pDu2Qo/rHr1KQJBAJ1rr0y4UARcalyzFpGyaaidS3H/9Gktvb0rKIord5hk/4ZDBPaz6CW3uEWAPbk/oZiRzSEGB/MUlABy2ShGnzU="; 
		String params = "Sv6Zhkfg2MaY5+Ga5TRwe9f/tpy2/cNDUZnTO6/gPgctBhJmniCDArdVm8PIxZ7fl0GRjFgkltkQ1akq4SmWdHX0v23jghUcIrnoKHGSTXgbFC/gJcTmMJHObQPhP64e3EZnRDlIF27Wi4EAfOuUvPkq/nb4F4vhu5ZSebj6aUE=";
		byte[] ori = RSACoder.decryptByPrivateKey(params, privateKey);
		System.out.println(new String(ori,"utf-8"));
	}

}
