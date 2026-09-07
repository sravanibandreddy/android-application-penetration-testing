package com.android.insecurebankv2;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoClass {

    // VULNERABILITY M5: Hardcoded symmetric encryption key
    private static final String STATIC_KEY = "1234567890123456";

    /**
     * VULNERABILITY M5: Weak MD5 hashing algorithm
     */
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : messageDigest) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * VULNERABILITY M5: Deprecated DES encryption
     */
    public static byte[] encryptData(byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(STATIC_KEY.substring(0, 8).getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}
