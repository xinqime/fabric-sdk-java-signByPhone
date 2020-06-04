package org.hyperledger.fabric.sdk.security.test;

/**
 * @author zhang_lan@inspur.com
 * @description
 * @date 2019/3/27
 */
public class PubException extends RuntimeException {


    /**
     * 请求参数错误
     */
    public static final String PARAM_ERROR = "0001";

    /**
     * json格式错误
     */
    public static final String JSON_ERROR = "0002";

    /**
     * 认证信息校验错误
     */
    public static final String AUTH_ERROR = "0003";

    /**
     * 短信相关错误
     */
    public static final String SMS_ERROR = "0004";

    /**
     * 用户不存在
     */
    public static final String USER_NOT_EXIST_ERROR = "0005";

    /**
     * 秘钥错误
     */
    public static final String SECRET_WRONG_ERROR = "0006";

    /**
     * 秘钥生成错误
     */
    public static final String SECRET_CREATE_ERROR = "0007";

    /**
     * 对称加密错误
     */
    public static final String ENCRYPT_ERROR = "0008";

    /**
     * 解密错误
     */
    public static final String DECRYPT_ERROR = "0009";

    /**
     * 文件上传错误
     */
    public static final String FILE_UPLOAD_ERROR = "0010";

    /**
     * 文件处理错误
     */
    public static final String FILE_DEAL_ERROR = "0011";

    /**
     * 压缩包中包含中文路径
     */
    public static final String ZIP_CONTAINS = "0012";

    /**
     * 压缩包解析异常
     */
    public static final String ZIP_ANALYSIS_ERROR = "0013";

    /**
     * 存证服务相关错误
     */
    public static final String PROOF_ERROR = "0014";

    /**
     * 网络请求错误
     */
    public static final String NETWORK_REQUEST_ERROR = "0015";

    /**
     * 同步用户错误
     */
    public static final String SYNC_USER_ERROR = "0016";

    /**
     * 注册用户错误
     */
    public static final String REGISTER_USER_ERROR = "0017";

    /**
     * 获取交易历史信息错误
     */
    public static final String GET_TRANSACTION_HISTORY_ERROR = "1001";

    /**
     * fabric用户注册失败
     */
    public static final String FABRIC_USER_REGISTER_ERROR = "1002";

    /**
     * fabric用户登记失败
     */
    public static final String FABRIC_USER_ENROLL_ERROR = "1003";

    /**
     * fabric写链异常
     */
    public static final String FABRIC_WRITE_CHAIN_ERROR = "1004";

    /**
     * 未知错误
     */
    public static final String UNKNOWN_ERROR = "9999";

    protected String errorCode;

    public String getCode() {
        return errorCode;
    }

    public void setCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public PubException(String errorCode, String errorMsg) {
        super(errorMsg);
        this.errorCode = errorCode;
    }

    public PubException(String errorCode, String errorMsg, Throwable t) {
        super(errorMsg, t);
        this.errorCode = errorCode;
    }

}
