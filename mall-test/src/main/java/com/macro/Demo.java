package com.macro;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
 
public class Demo {
 
	public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	public static final String PLAIN_TEXT = "test string";
    private static final String ENCODING = "UTF-8";
 
	public static void main(String[] args) {
		// 公私钥对
		Map<String, byte[]> keyMap = RSA.generateKeyBytes();
//		PublicKey publicKey = RSA.restorePublicKey(keyMap.get(RSA.PUBLIC_KEY));
		PrivateKey privateKey = RSA.restorePrivateKey(keyMap.get(RSA.PRIVATE_KEY));
		// 签名
		byte[] sing_byte = sign(privateKey, "3003c1217da714b43a0f2b81795e05080dafd4bb8a65ba7776dcc528ab470b65");
		BASE64Encoder encoder = new BASE64Encoder();
		String data = encoder.encode(sing_byte);
		System.out.println("BASE64加密：" + data);
	}
 
	/**
	 * 签名
	 * 
	 * @param privateKey
	 *            私钥
	 * @param plain_text
	 *            明文
	 * @return
	 */
	public static byte[] sign(PrivateKey privateKey, String plain_text) {
		MessageDigest messageDigest;
		byte[] signed = null;
		try {
			//messageDigest = MessageDigest.getInstance(ENCODE_ALGORITHM);
			//messageDigest.update(plain_text.getBytes());
			//byte[] outputDigest_sign = messageDigest.digest();
			//System.out.println("SHA-256加密后-----》" +bytesToHexString(outputDigest_sign));
			Signature Sign = Signature.getInstance(SIGNATURE_ALGORITHM);
			Sign.initSign(privateKey);
			Sign.update(plain_text.getBytes());
			signed = Sign.sign();
			System.out.println("SHA256withRSA签名后-----》" + bytesToHexString(signed));
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return signed;
	}
 
	/**
	 * 验签
	 * 
	 * @param publicKey
	 *            公钥
	 * @param plain_text
	 *            明文
	 * @param signed
	 *            签名
	 */
	public static boolean verifySign(PublicKey publicKey, String plain_text, byte[] signed) {
 
		MessageDigest messageDigest;
		boolean SignedSuccess=false;
		try {
			//messageDigest = MessageDigest.getInstance(ENCODE_ALGORITHM);
			//messageDigest.update(plain_text.getBytes());
			//byte[] outputDigest_verify = messageDigest.digest();
			//System.out.println("SHA-256加密后-----》" +bytesToHexString(outputDigest_verify));
			Signature verifySign = Signature.getInstance(SIGNATURE_ALGORITHM);
			verifySign.initVerify(publicKey);
			verifySign.update(plain_text.getBytes());
			SignedSuccess = verifySign.verify(signed);
			System.out.println("验证成功？---" + SignedSuccess);
			
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return SignedSuccess;
	}
 
	/**
	 * bytes[]换成16进制字符串
	 * 
	 * @param src
	 * @return
	 */
	public static String bytesToHexString(byte[] src) {
		StringBuilder stringBuilder = new StringBuilder("");
		if (src == null || src.length <= 0) {
			return null;
		}
		for (int i = 0; i < src.length; i++) {
			int v = src[i] & 0xFF;
			String hv = Integer.toHexString(v);
			if (hv.length() < 2) {
				stringBuilder.append(0);
			}
			stringBuilder.append(hv);
		}
		return stringBuilder.toString();
	}
}