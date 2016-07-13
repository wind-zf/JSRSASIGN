package com.rsa.test01;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;


public class TestSign {
	public static RSAPublicKey getPublicKey() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		FileInputStream fis = new FileInputStream(new File("d:/public"));  
		PEMReader reader = new PEMReader(new InputStreamReader(fis), new PasswordFinder() {  
		      
		    @Override  
		    public char[] getPassword() {  
		        return "".toCharArray();  
		    }  
		});
		//PEMReader pemReader = new PEMReader(sr);
		RSAPublicKey keyPair = (RSAPublicKey) reader.readObject(); 
		return keyPair;
	}
	public static void main(String[] args) throws Exception {
		String str = "aaa";
		try {
			//byte[] signautreResult = RsaKeyTools.sign(str,getPublicKey().getEncoded());
			//String signatureStr = RsaKeyTools.bytes2String(signautreResult);
			//byte[] signatureResult2 = RsaKeyTools.hexStringToByteArray(signatureStr);
			
			System.out.println();
			String signStr = "7663fd8a3db83fbe1709a44f17f4486b8ca8eaad3295ca43acb27a601567fe3706f0b3fcdf625e095e27538532e4ba1fe58fe333eb95db55162325cf616f5609011dfddf2627f54bd8521addbdb505b640ebf1f0a2a12a8bd282e343142a64885b8685aa444344ed96044f0db89644f2c8294412b5ba262299bf1b23924322ed";
			boolean b = RsaKeyTools.verify(str,getPublicKey().getEncoded(),RsaKeyTools.hexStringToByteArray(signStr));
			System.out.print("iii   " + b);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
