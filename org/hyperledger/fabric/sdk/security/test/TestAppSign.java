package org.hyperledger.fabric.sdk.security.test;

import static java.lang.String.format;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.hyperledger.fabric.sdk.exception.CryptoException;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import sun.misc.BASE64Encoder;

public class TestAppSign {
	
	private ECPrivateKey privateKey;
	
	public TestAppSign() {
		init();
	}
	
	private void init() {
		File file = new File("C:/Users/jiangmingrun/Desktop/prvKey.txt");
		StringBuilder result = new StringBuilder();
		
		try {
			BufferedReader br = new BufferedReader(new FileReader(file));
			String s = null;
			while((s = br.readLine())!= null) {
				result.append(s);
			}		
			br.close();
		}catch(Exception e){
			e.printStackTrace();
		}
		PrivateKey pk = null;
		try {
			pk = getPrivateKey(SecretUtil.defaultDecrypt(result.toString()));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		privateKey = (ECPrivateKey)pk;
	}
	
    public byte[] ecdsaSignToBytes(byte[] data,String curveName,Provider SECURITY_PROVIDER
    								,String DEFAULT_SIGNATURE_ALGORITHM) throws CryptoException {
        if (data == null) {
            throw new CryptoException("Data that to be signed is null.");
        }
        if (data.length == 0) {
            throw new CryptoException("Data to be signed was empty.");
        }

        try {
            X9ECParameters params = ECNamedCurveTable.getByName(curveName);
            BigInteger curveN = params.getN();

            Signature sig = SECURITY_PROVIDER == null ? Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM) :
                    Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM, SECURITY_PROVIDER);
            sig.initSign(privateKey);
            sig.update(data);
            byte[] signature = sig.sign();

            BigInteger[] sigs = decodeECDSASignature(signature);

            sigs = preventMalleability(sigs, curveN);

            try (ByteArrayOutputStream s = new ByteArrayOutputStream()) {

                DERSequenceGenerator seq = new DERSequenceGenerator(s);
                seq.addObject(new ASN1Integer(sigs[0]));
                seq.addObject(new ASN1Integer(sigs[1]));
                seq.close();
                return s.toByteArray();
            }

        } catch (Exception e) {
            throw new CryptoException("Could not sign the message using private key", e);
        }

    }
    
    /**
     * Decodes an ECDSA signature and returns a two element BigInteger array.
     *
     * @param signature ECDSA signature bytes.
     * @return BigInteger array for the signature's r and s values
     * @throws Exception
     */
    private static BigInteger[] decodeECDSASignature(byte[] signature) throws Exception {

        try (ByteArrayInputStream inStream = new ByteArrayInputStream(signature)) {
            ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
            ASN1Primitive asn1 = asnInputStream.readObject();

            BigInteger[] sigs = new BigInteger[2];
            int count = 0;
            if (asn1 instanceof ASN1Sequence) {
                ASN1Sequence asn1Sequence = (ASN1Sequence) asn1;
                ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
                for (ASN1Encodable asn1Encodable : asn1Encodables) {
                    ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
                    if (asn1Primitive instanceof ASN1Integer) {
                        ASN1Integer asn1Integer = (ASN1Integer) asn1Primitive;
                        BigInteger integer = asn1Integer.getValue();
                        if (count < 2) {
                            sigs[count] = integer;
                        }
                        count++;
                    }
                }
            }
            if (count != 2) {
                throw new CryptoException(format("Invalid ECDSA signature. Expected count of 2 but got: %d. Signature is: %s", count,
                        DatatypeConverter.printHexBinary(signature)));
            }
            return sigs;
        }

    }
    
    private BigInteger[] preventMalleability(BigInteger[] sigs, BigInteger curveN) {
        BigInteger cmpVal = curveN.divide(BigInteger.valueOf(2L));

        BigInteger sval = sigs[1];

        if (sval.compareTo(cmpVal) == 1) {

            sigs[1] = curveN.subtract(sval);
        }

        return sigs;
    }
    
	private PrivateKey getPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] keyBytes = HexBin.decode(key);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PrivateKey pk = keyFactory.generatePrivate(keySpec);
		return pk;
	}
    public static void main(String []args) {
    	TestAppSign test = new TestAppSign();
    	System.out.println(new BASE64Encoder().encodeBuffer(test.privateKey.getEncoded()));
//    	byte [] test1 = {1,2,3,4,5};
//    	System.out.println(Arrays.toString(test1));
    }
}
