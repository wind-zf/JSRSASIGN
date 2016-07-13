package com.rsa.success;

public class TestSignParam {
	public static void main(String[] args) {
		String str = "69578,2,89,31,lrtvfeb";
		String signParam = "64708d898959f782cc12dc3fa52058885a26c6230760cf5a57d9ce97447a0dae5927e68752e30f51cf8cc53bb368ea0ca5f76b9d739ce00ce747f51d425cd438d1e84f5a65f9dce5553c4a710119ec860c6330c85aabf1aff22bc4676cabe62dec0ba0c2d54716cfcca08e410e8d4af0938c11543f2ffa42f400f92d4f34d3dd";
		boolean res = RsaKeyUtils.verify(str, RsaKeyUtils.loadPublicKey().getEncoded(), RsaKeyUtils.hexStringToByteArray(signParam));
		System.out.println("verify:"+res);
	}

}
