package org.hyperledger.fabric.sdk.security.test;

/**
 * @author zhang_lan@inspur.com
 * @description
 * @date 2019/9/10
 */
public class SecretUtil {

    public static void main(String[] args) {
            String src = "4E4CFFE08A0C92BAE0454D6338978332";
//            String str1 = defaultEncrypt(src);
//            System.out.println(str1);
            String str2 = defaultDecrypt(src);
            System.out.println(str2);
    }

    public static String defaultEncrypt(String source) {
        return encrypt(source, SecretConst.DEFAULT_SECRET);
    }

    public static String defaultDecrypt(String eSource) {
        return decrypt(eSource, SecretConst.DEFAULT_SECRET);
    }

    public static String encrypt(String source, String secret) {
        String SecretHex = null;
        try {
            SecretHex = AesUtil.getSecretKey(secret);
        } catch (Exception e) {
            throw new PubException(PubException.SECRET_WRONG_ERROR, "获取秘钥错误", e);
        }
        String result = null;
        try {
            result = AesUtil.encrypt(source, SecretHex);
        } catch (Exception e) {
            throw new PubException(PubException.ENCRYPT_ERROR, "加密错误", e);
        }
        return result;
    }

    public static String decrypt(String eSource, String secret) {
        String SecretHex = null;
        try {
        	for(int i =0; i<10;i++) {
        		SecretHex = AesUtil.getSecretKey(secret);
        		System.out.println("1111"+SecretHex);
        	}
        } catch (Exception e) {
            throw new PubException(PubException.SECRET_WRONG_ERROR, "获取默认秘钥错误", e);
        }
        String result = null;
        try {
            result = AesUtil.decrypt(eSource, SecretHex);
        } catch (Exception e) {
            throw new PubException(PubException.DECRYPT_ERROR, "解密错误", e);
        }
        return result;
    }

}
