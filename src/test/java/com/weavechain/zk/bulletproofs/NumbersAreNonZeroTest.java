package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumbersAreNonZeroParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class NumbersAreNonZeroTest extends ZkTest {

    @Test
    protected void testNonZero() throws Exception {
        List<Long> values = List.of(16L, -17L, 1021L, 25L, 26L);

        NumbersAreNonZeroParams params = new NumbersAreNonZeroParams(values.size());

        Truth.assertThat(testNonZero(params, values)).isTrue();
    }

    @Test
    protected void testOneZero() throws Exception {
        List<Long> values = List.of(16L, -17L, 1021L, 0L, 26L);

        NumbersAreNonZeroParams params = new NumbersAreNonZeroParams(values.size());

        Truth.assertThat(testNonZero(params, values)).isFalse();
    }

    @Test
    protected void testAllZero() throws Exception {
        List<Long> values = List.of(0L, 0L, 0L, 0L, 0L);

        NumbersAreNonZeroParams params = new NumbersAreNonZeroParams(values.size());

        Truth.assertThat(testNonZero(params, values)).isFalse();
    }

    private boolean testNonZero(NumbersAreNonZeroParams params, List<Long> values) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(GadgetType.numbers_are_non_zero, values, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(GadgetType.numbers_are_non_zero, params, proof2, pc, bg2);
    }
}
