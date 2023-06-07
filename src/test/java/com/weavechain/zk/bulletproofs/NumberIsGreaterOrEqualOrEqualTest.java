package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumberIsGreaterOrEqualParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class NumberIsGreaterOrEqualOrEqualTest extends ZkTest {

    @Test
    protected void testIsGreater() throws Exception {
        NumberIsGreaterOrEqualParams params = new NumberIsGreaterOrEqualParams(
                10L,
                31
        );

        Long value = 10L;

        Truth.assertThat(testIsGreater(params, value)).isTrue();
    }

    @Test
    protected void testIsLess() throws Exception {
        NumberIsGreaterOrEqualParams params = new NumberIsGreaterOrEqualParams(
                10L,
                10
        );

        Long value = 4L;

        Truth.assertThat(testIsGreater(params, value)).isFalse();
    }

    @Test
    protected void testIsEqual() throws Exception {
        NumberIsGreaterOrEqualParams params = new NumberIsGreaterOrEqualParams(
                10L,
                10
        );

        Long value = 10L;

        Truth.assertThat(testIsGreater(params, value)).isTrue();
    }

    private boolean testIsGreater(NumberIsGreaterOrEqualParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(GadgetType.number_is_greater_or_equal, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(GadgetType.number_is_greater_or_equal, params, proof2, pc, bg2);
    }
}
