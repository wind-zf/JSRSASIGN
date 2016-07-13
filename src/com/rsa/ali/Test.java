package com.rsa.ali;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Test {
	public static void main(String[] args) {
		KeyPair kp = RSA.generateRSAKeyPair(1024);
		String pbKeyStr = RSA.convertToPemKey((RSAPublicKey) kp.getPublic(), null);
		System.out.println(pbKeyStr);
		String prKeyStr = RSA.convertToPemKey(null,(RSAPrivateKey) kp.getPrivate());
		System.out.println(prKeyStr);
		String ali_public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPQ7ExjHZmCnazOEW34nN6hBvoHaFHEHASQ3EAlIBTNFUQ6j5o3hBQjguyWqP9i9UKSKIswNDK828RtpNFjPLenyekQ5fwiZ1ODCsE95LfjPPcCXlRHhcSdwWrqRKT31FUnJ1koyjMPrnU6k2yVc7bYuGgLFaQrXKiCtlt5Sfh/wIDAQAB";
		
		System.out.println(RSA.PEM_PRIVATEKEY);
		boolean res = RSA.verify("aaa", 
				"4c4d6d7bc5fbbc36b2b6c06ff49ac42d45fc0bbe40f63425d1416a87be1734a65cd3921e3dc59bc6f3f2026032334d1e3d1f08a9d56ddbc9a97607f61b2d7da18913d8bdf7a6fa7ba958fe24d03eb7dd7d3928c74f174b8cecdf012258f6278aa4e99b21d9d69506e97c6b7b38fb6a97cd677155f6ec9d09ffaafd68ffaee906", 
				ali_public_key, 
				"utf-8");
		System.out.println(res);
		
	}

}
