package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumberInRangeParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class NumberInRangeTest extends ZkTest {

    @Test
    protected void testInRange() throws Exception {
        NumberInRangeParams params = new NumberInRangeParams(
                10L,
                100L,
                31
        );

        Long value = 16L;

        Truth.assertThat(testInRange(params, value)).isTrue();
    }

    @Test
    protected void testInRangeLarge() throws Exception {
        NumberInRangeParams params = new NumberInRangeParams(
                10L,
                1111111128L,
                31
        );

        Long value = 16L;

        Truth.assertThat(testInRange(params, value)).isTrue();
    }

    @Test
    protected void testNotInRange() throws Exception {
        NumberInRangeParams params = new NumberInRangeParams(
                10L,
                1000L,
                10
        );

        Long value = 1116L;

        Truth.assertThat(testInRange(params, value)).isFalse();
    }

    private boolean testInRange(NumberInRangeParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(GadgetType.number_in_range, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(GadgetType.number_in_range, params, proof2, pc, bg2);
    }
}
