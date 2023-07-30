package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.Gadgets;
import com.weavechain.zk.bulletproofs.gadgets.MiMC;
import com.weavechain.zk.bulletproofs.gadgets.MiMCStringHashPreImageParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class MiMCStringHashPreimageTest extends ZkTest {

    static final Logger logger = LoggerFactory.getLogger(MiMCStringHashPreimageTest.class);

    @Test
    protected void testMatch() throws Exception {
        String data = "Piece of data to be hashed";
        MiMCStringHashPreImageParams params = MiMCStringHashPreImageParams.from(data, 0, MiMC.DEFAULT_MIMC_ROUNDS);

        String value = data;

        Truth.assertThat(testMatch(params, value, 4096)).isTrue();
    }

    @Test
    protected void testMatchLong() throws Exception {
        StringBuilder data = new StringBuilder();
        for (int i = 0; i < 1024; i++) {
            data.append((char)('0' + (100 * Math.random())));
        }
        MiMCStringHashPreImageParams params = MiMCStringHashPreImageParams.from(data.toString(), 0, 91);

        String value = data.toString();

        Truth.assertThat(testMatch(params, value, 32768)).isTrue();
    }

    @Test
    protected void testNotMatch() throws Exception {
        String data = "Piece of data to be hashed";
        MiMCStringHashPreImageParams params = MiMCStringHashPreImageParams.from(data, 0, MiMC.DEFAULT_MIMC_ROUNDS);

        String value = "Different piece of data to be hashed";

        Truth.assertThat(testMatch(params, value, 4096)).isFalse();
    }

    private boolean testMatch(MiMCStringHashPreImageParams params, String value, int generators) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        long start = System.currentTimeMillis();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(generators, 1);
        Proof proof = bulletProofs.generate(Gadgets.mimc_string_hash_preimage, value, params, rnd, pc, bg1);

        long mid = System.currentTimeMillis();

        byte[] serialization = proof.serialize();
        logger.info("Generate (ms): " + (mid - start));
        logger.info("Proof size: " + serialization.length);
        Proof proof2 = Proof.deserialize(serialization);

        BulletProofGenerators bg2 = new BulletProofGenerators(generators, 1);
        boolean check = bulletProofs.verify(Gadgets.mimc_string_hash_preimage, params, proof2, pc, bg2);

        long end = System.currentTimeMillis();
        logger.info("Verify (ms): " + (end - mid));

        return check;
    }
}
