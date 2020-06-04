package org.hyperledger.fabric.sdk.security.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

/**
 * @author zhang_lan@inspur.com
 * @description
 * @date 2019/4/13
 */
public class AesUtil {
    private static final String KEY_ALGORITHM = "AES";

    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";

    private static final String CBC_IV = "1234567890123456";

    private static final int KEY_SIZE = 128;

    private static final int CACHE_SIZE = 1024;

    /**
     * 获取随机AES秘钥
     * @return
     * @throws Exception
     */
    public static String getSecretKey() throws Exception {
        return getSecretKey(null);
    }

    /**
     * 根据种子获取AES秘钥
     * @param seed
     * @return
     * @throws Exception
     */
    public static String getSecretKey(String seed) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        if (seed != null && !"".equals(seed)) {
            secureRandom.setSeed(seed.getBytes());
        }
        keyGenerator.init(KEY_SIZE, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        return HexBin.encode(secretKey.getEncoded());
    }

    /**
     * 使用AES算法对文本加密
     * @param src
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptWithMd5Key(String src, String key) throws Exception {
        byte[] input = src.getBytes("utf-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] thedigest = md.digest(key.getBytes("utf-8"));
        SecretKeySpec skc = new SecretKeySpec(thedigest, KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
//        IvParameterSpec iv = new IvParameterSpec(CBC_IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, skc);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        return HexBin.encode(cipherText);
    }
    /**
     * 使用AES算法对文本加密
     * @param src
     * @param key
     * @return
     * @throws Exception
     */
    public static String encrypt(String src, String key) throws Exception {
        Key k = toKey(HexBin.decode(key));
        byte[] raw = k.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(CBC_IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        byte[] data = cipher.doFinal(src.getBytes());
        return HexBin.encode(data);
    }

    /**
     * 使用AES对加密文本解密
     * @param encData·
     * @param key
     * @return
     * @throws Exception
     */
    public static String decrypt(String encData, String key) throws Exception {
        Key k = toKey(HexBin.decode(key));
        byte[] raw = k.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        IvParameterSpec iv = new IvParameterSpec(CBC_IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        byte[] data = cipher.doFinal(HexBin.decode(encData));
        return new String(data, "UTF-8");
    }

    /**
     * 使用AES对加密文本解密
     * @param encData·
     * @param key
     * @return
     * @throws Exception
     */
    public static String decryptWithMd5Key(String encData, String key) throws Exception {
        byte[] keyb = key.getBytes("utf-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] thedigest = md.digest(keyb);
        SecretKeySpec skey = new SecretKeySpec(thedigest, KEY_ALGORITHM);
        Cipher dcipher = Cipher.getInstance(KEY_ALGORITHM);
        dcipher.init(Cipher.DECRYPT_MODE, skey);
        byte[] data = dcipher.doFinal(HexBin.decode(encData));
        return new String(data);
    }

    /**
     * 使用AES对文件进行加密
     * @param key
     * @param sourceFilePath
     * @param destFilePath
     * @throws Exception
     */
    public static void encryptFile(String key, String sourceFilePath, String destFilePath) throws Exception {
        File sourceFile = new File(sourceFilePath);
        File destFile = new File(destFilePath);
        if (sourceFile.exists() && sourceFile.isFile()) {
            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }
            destFile.createNewFile();
            InputStream in = new FileInputStream(sourceFile);
            OutputStream out = new FileOutputStream(destFile);
            Key k = toKey(HexBin.decode(key));
            byte[] raw = k.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(raw, KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(CBC_IV.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
            CipherInputStream cin = new CipherInputStream(in, cipher);
            byte[] cache = new byte[CACHE_SIZE];
            int nRead = 0;
            while ((nRead = cin.read(cache)) != -1) {
                out.write(cache, 0, nRead);
                out.flush();
            }
            out.close();
            cin.close();
            in.close();
        }
    }

    /**
     * 使用AES对加密文件进行解密
     * @param key
     * @param sourceFilePath
     * @param destFilePath
     * @throws Exception
     */
    public static void decryptFile(String key, String sourceFilePath, String destFilePath) throws Exception {
        File sourceFile = new File(sourceFilePath);
        File destFile = new File(destFilePath);
        if (sourceFile.exists() && sourceFile.isFile()) {
            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }
            destFile.createNewFile();
            FileInputStream in = new FileInputStream(sourceFile);
            FileOutputStream out = new FileOutputStream(destFile);
            Key k = toKey(HexBin.decode(key));
            byte[] raw = k.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(raw, KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(CBC_IV.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
            CipherOutputStream cout = new CipherOutputStream(out, cipher);
            byte[] cache = new byte[CACHE_SIZE];
            int nRead = 0;
            while ((nRead = in.read(cache)) != -1) {
                cout.write(cache, 0, nRead);
                cout.flush();
            }
            cout.close();
            out.close();
            in.close();
        }
    }

    private static Key toKey(byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        return secretKey;
    }

    public static void main(String[] args) throws Exception {
        // 根据传入的seed生成秘钥字符串，seed就相当你自己设置的密码，key是根据密码生成的，加密解密时用的是key而不是密码
        String key = getSecretKey("sasdfasdfasdfasdfss");
        System.out.println("================秘钥===============");
        System.out.println(key);

        String src = "这是一条原文数据";
        System.out.println("================原文===============");
        System.out.println(src);

        String encryptedData = encrypt(src, key);
        System.out.println("================加密后的数据===============");
        System.out.println(encryptedData);

        String decryptedData = decrypt(encryptedData, key);
        System.out.println("================解密后的数据===============");
        System.out.println(decryptedData);
    }

}
