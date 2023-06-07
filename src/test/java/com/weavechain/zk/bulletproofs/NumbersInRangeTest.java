package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumbersInRangeParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class NumbersInRangeTest extends ZkTest {

    @Test
    protected void testInRange() throws Exception {
        NumbersInRangeParams params = new NumbersInRangeParams(
                5,
                10L,
                100L,
                31
        );

        List<Long> values = List.of(16L, 17L, 21L, 25L, 26L);

        Truth.assertThat(testInRange(params, values)).isTrue();
    }

    @Test
    protected void testNotInRange() throws Exception {
        NumbersInRangeParams params = new NumbersInRangeParams(
                5,
                10L,
                1000L,
                10
        );

        List<Long> values = List.of(16L, 17L, 1021L, 25L, 26L);

        Truth.assertThat(testInRange(params, values)).isFalse();
    }

    private boolean testInRange(NumbersInRangeParams params, List<Long> values) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(512, 1);
        Proof proof = bulletProofs.generate(GadgetType.numbers_in_range, values, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(512, 1);
        return bulletProofs.verify(GadgetType.numbers_in_range, params, proof2, pc, bg2);
    }
}
