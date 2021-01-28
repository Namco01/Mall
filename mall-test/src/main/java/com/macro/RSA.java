package com.macro;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
 
public class RSA {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String PUBLIC_KEY = "publicKey";
    public static final String PRIVATE_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCNxPWdH+E2PMSYyH6xGE0F1b7OKMeZJ56H/IbeRGBDnJcaRHbxTPpwOVg50TufUREJa5mNBO8Wl9t4SdMwKfYduIOWPHjVC+a7RWTVHC0wP+lv9QthI9u1Zg0ZI2eBdxH1C9wpeWXAgZ/4r8ybUBFMyUAJeyDul8GA+VHolNTMiNn/B7bq1jgaU27JxTWa3//YTLufrwPv1lNIPk1zpKfWn5fmIcawkLFmIu13SSJ56p1xzy49m/JsZUugD8SObYKCtqUCJVQcC4LF5SEGXlsgVI3sVT/plXXib5YlV6+HN5SyTsv1GN+18Q0HXj7RFpUL5hh7olpAVqZRfX9x9c1XAgMBAAECggEBAIiwInBAUJBOvu7gQObXG0xI7hMv1mKghIVwwUiEfJwz2qyE3nmBUuXpJFt6lRXiv55plD8XRr5t5DlyVKDXlGjLgnPUEly3gNuG6NVguWEP/i7oAPTD8g5QOsjGDgIRn8q4iKmkVqrpUCgiuA/3fvaeA5Qgl3vz7apAuOyasyIQRu5ahJR7JNWobQ9aHWOTGLXrWJ//0hS7tw/w6o+dQ4KBfLO8a50KyU4UPi7GQ411MxVwkxFKrr0FuHZH/whbV7/+vl7tYzz58MbuAHXBCBZncNg2zW50rxHUu8MnnaAmelHW+1O9DdsWn2BV7RTkNrKmVtyRYg7FDmp6XO0V8mECgYEA8bIrrOlPI6NUkXv8geSX5jT+YmkWtgRxmeimrVTSHHROGG9S/aXSR9lDYVKzYVG48pELRUrCb5pj2Bu1jzNczBZV6LqxQesrgo2aNh1KbrDVZ2g+8fcbHSLcgHjLr81ydY/oJHyj5sGfYToNm93fpl66ht0ySolpkds04xmm0Z0CgYEAlijYRHrYDdVfNkYGXIC4WvFBOlP5UaUBVgCDmfXKYWFLGZMQ145nlt+1xLAxyfUxIWlMhWwkPCYcZSiowG5KrfugFv3In4bTJIh7ole9aRuJjrgsYtTDtAphZE3YBCq9J5eo1Un6SiCwI8rlI5Qp1wExK3q4Nt3fK7PpEJsxkoMCgYEA0OVAcHM57kBlgFScGpw7WUGmN+JCOdE/alm1bYwpCWTQdrgJD6d5RpYWcZBr74oVgrkv95S01oanEwpn8rve0ZngaISrXaDney/uACVyxpbZ60UjWjhL2/PchsFgsrKr4cYeSyLa+j+RBBSL3JJ4ka/AIX4e0GNRtjmyzTHHh9UCgYBQYWjzr3a8YP3oxa9eESGevQqXuJ/7zoJakUfhQKunWTekZw9a9EYLg5F/ynm8jF5SblWiDnOPJy+IDy3WZLPhUpMt+4hLrRaVteHI04L3IuCN35UTCqYAWJYt5WW/RUmgShT8p+8tgzYG0vO6CfQjveWeSsEVzctLT7FxTEJLFQKBgBqjdAowHyr1ZiQGXGBOnZwZC2gDjlMXNTFItMz5aOBncmfsJNhExdreS2lpWwSbAxDwBRd2NWS3hXybAMhQ1I7s7C8A7IZ+cEmWs1yR1jtYaO1jF/1rbSgkGnuYUYgpNB4u3uyMQvKIDLg1+mKJu9Nv9M3HbjrciRQyuylGUa+E";
    public static final int KEY_SIZE = 2048;
    /**
     * 生成密钥对
     * 
     * @return
     */
    public static Map<String, byte[]> generateKeyBytes() {
 
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            Map<String, byte[]> keyMap = new HashMap<String, byte[]>();
            keyMap.put(PUBLIC_KEY, publicKey.getEncoded());
            keyMap.put(PRIVATE_KEY, privateKey.getEncoded());
            return keyMap;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
 
    /**
     * 还原公钥
     * 
     * @param keyBytes
     * @return
     */
    public static PublicKey restorePublicKey(byte[] keyBytes) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
 
    /**
     * 还原私钥
     * 
     * @param keyBytes
     * @return
     */
    public static PrivateKey restorePrivateKey(byte[] keyBytes) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                keyBytes);
        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privateKey = factory
                    .generatePrivate(pkcs8EncodedKeySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
}