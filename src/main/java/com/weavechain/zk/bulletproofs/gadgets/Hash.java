package com.weavechain.zk.bulletproofs.gadgets;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Hash {

    static final Logger logger = LoggerFactory.getLogger(Hash.class);

    public static final String HmacSHA256 = "HmacSHA256";

    public static final String HmacSHA512 = "HmacSHA512";

    public static final String SHA256 = "SHA-256";

    public static final String SHA512 = "SHA-512";

    public static final String Keccak256 = "Keccak-256";

    public static final String Keccak512 = "Keccak-512";

    public static final String SaltedKeccak256 = "SaltedKeccak256";

    public static final String SaltedKeccak512 = "SaltedKeccak512";

    public static final String SaltedSHA256 = "SaltedSHA256";

    public static final String SaltedSHA512 = "SaltedSHA512";

    public static final String Blake2 = "Blake2";

    public static final String SaltedXMSS256 = "SaltedXMSS256";

    public static final String SaltedXMSS512 = "SaltedXMSS512";

    private static final int XMSSMT_HEIGHT = 10;

    private static final int XMSSMT_LAYERS = 5;

    private static final SecureRandom RND = new SecureRandom();

    private static String hash = SHA256;

    public static void initHashing(String hash) {
        Hash.hash = hash;
    }

    public static byte[] signString(byte[] secret, String data, String digest) {
        return signBytes(secret, data.getBytes(StandardCharsets.UTF_8), digest);
    }

    public static int getHashLength(String digest) {
        if (digest == null
                || HmacSHA256.equals(digest)
                || SaltedSHA256.equals(digest)
                || SaltedKeccak256.equals(digest)
                || SHA256.equals(digest)
                || Keccak256.equals(digest)
        ) {
            return 32;
        } else if (HmacSHA512.equals(digest)
                || SaltedSHA512.equals(digest)
                || SaltedKeccak512.equals(digest)
                || SHA512.equals(digest)
                || Keccak512.equals(digest)
                || Blake2.equals(digest)
        ) {
            return 64;
        } else if (SaltedXMSS256.equals(digest)) {
            return 11074;
        } else if (SaltedXMSS512.equals(digest)) {
            return 42626;
        } else {
            return 32;
        }
    }

    public static byte[] signBytes(byte[] secret, byte[] data, String digest) {
        try {
            String hash = digest != null ? digest : Hash.hash;

            byte[] result = null;
            if (hash == null || HmacSHA256.equals(hash) || SHA256.equals(hash)) {
                if (secret != null) {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(new SecretKeySpec(secret, "HmacSHA256"));
                    result = mac.doFinal(data);
                } else {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    result = md.digest(data);
                }
            } else if (HmacSHA512.equals(hash) || SHA512.equals(hash)) {
                if (secret != null) {
                    Mac mac = Mac.getInstance("HmacSHA512");
                    mac.init(new SecretKeySpec(secret, "HmacSHA512"));
                    result = mac.doFinal(data);
                } else {
                    MessageDigest md = MessageDigest.getInstance("SHA-512");
                    result = md.digest(data);
                }
            } else if (SaltedSHA256.equals(hash)) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                result = md.digest(getSaltedBytes(secret, data));
            } else if (SaltedSHA512.equals(hash)) {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                result = md.digest(getSaltedBytes(secret, data));
            } else if (SaltedKeccak256.equals(hash) || Keccak256.equals(hash)) {
                MessageDigest md = MessageDigest.getInstance("Keccak-256");
                result = md.digest(getSaltedBytes(secret, data));
            } else if (SaltedKeccak512.equals(hash) || Keccak512.equals(hash)) {
                MessageDigest md = MessageDigest.getInstance("Keccak-512");
                result = md.digest(getSaltedBytes(secret, data));
            } else if (Blake2.equals(hash)) {
                Blake2bDigest b2 = new Blake2bDigest(null, 64, secret, null);
                b2.update(data, 0, data.length);
                result = new byte[64];
                b2.doFinal(result, 0);
            } else if (SaltedXMSS256.equals(hash)) {
                XMSSMTParameters params = new XMSSMTParameters(XMSSMT_HEIGHT, XMSSMT_LAYERS, new SHA256Digest());
                XMSSMT mt = new XMSSMT(params, RND);
                mt.generateKeys();
                result = mt.sign(getSaltedBytes(secret, data));
            } else if (SaltedXMSS512.equals(hash)) {
                XMSSMTParameters params = new XMSSMTParameters(XMSSMT_HEIGHT, XMSSMT_LAYERS, new SHA512Digest());
                XMSSMT mt = new XMSSMT(params, RND);
                mt.generateKeys();
                result = mt.sign(getSaltedBytes(secret, data));
            }
            return result;
        } catch (Exception e) {
            logger.error("Failed signing request", e);
            return null;
        }
    }

    private static byte[] getSaltedBytes(byte[] secret, byte[] data) {
        if (secret != null) {
            byte[] salted = new byte[secret.length + data.length];
            System.arraycopy(secret, 0, salted, 0, secret.length);
            System.arraycopy(data, 0, salted, secret.length, data.length);
            return salted;
        } else {
            return data;
        }
    }
}
