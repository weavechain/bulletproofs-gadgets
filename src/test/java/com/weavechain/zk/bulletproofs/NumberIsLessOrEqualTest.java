package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumberIsLessOrEqualParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class NumberIsLessOrEqualTest extends ZkTest {

    @Test
    protected void testIsGreater() throws Exception {
        NumberIsLessOrEqualParams params = new NumberIsLessOrEqualParams(
                10L,
                31
        );

        Long value = 16L;

        Truth.assertThat(testIsLess(params, value)).isFalse();
    }

    @Test
    protected void testIsLess() throws Exception {
        NumberIsLessOrEqualParams params = new NumberIsLessOrEqualParams(
                10L,
                10
        );

        Long value = 4L;

        Truth.assertThat(testIsLess(params, value)).isTrue();
    }

    @Test
    protected void testIsEqual() throws Exception {
        NumberIsLessOrEqualParams params = new NumberIsLessOrEqualParams(
                10L,
                10
        );

        Long value = 10L;

        Truth.assertThat(testIsLess(params, value)).isTrue();
    }

    private boolean testIsLess(NumberIsLessOrEqualParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(GadgetType.number_is_less_or_equal, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(GadgetType.number_is_less_or_equal, params, proof2, pc, bg2);
    }
}
