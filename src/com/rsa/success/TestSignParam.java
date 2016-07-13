package com.rsa.success;

public class TestSignParam {
	public static void main(String[] args) {
		String str = "69578,2,89,31,lrtvfeb";
		String signParam = "9eeb4127e9473de414f7d34c651f2e9185a7ea61179863b6de21d0674dcef99a9c6d87a8e7e10a6029cc37748fd6d24c19728ee9458182e440029036aff83e9d441dd39b60923808e3a9f8a334a18780d46f01cd274f90d8acb4f1f18ba86c616b85ee78214ba6b1b9baf7b062c8dc3d4903a7c4629725f7b3d8076ab33ce76e";
		boolean res = RsaKeyUtils.verify(str, RsaKeyUtils.loadPublicKey().getEncoded(), RsaKeyUtils.hexStringToByteArray(signParam));
		System.out.println("verify:"+res);
	}

}
