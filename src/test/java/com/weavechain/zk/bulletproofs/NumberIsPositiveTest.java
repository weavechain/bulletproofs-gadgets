package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumberIsPositiveParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class NumberIsPositiveTest extends ZkTest {

    @Test
    protected void testPositive() throws Exception {
        NumberIsPositiveParams params = new NumberIsPositiveParams(8);

        Long value = 128L;

        Truth.assertThat(testPositive(params, value)).isTrue();
    }

    @Test
    protected void testNegative() throws Exception {
        NumberIsPositiveParams params = new NumberIsPositiveParams(7);

        Long value = -5L;

        Truth.assertThat(testPositive(params, value)).isFalse();
    }

    private boolean testPositive(NumberIsPositiveParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(GadgetType.number_is_positive, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(GadgetType.number_is_positive, params, proof2, pc, bg2);
    }
}
