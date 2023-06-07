package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumbersArePositiveParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class NumbersArePositiveTest extends ZkTest {

    @Test
    protected void testPositive() throws Exception {
        List<Long> values = List.of(16L, 17L, 21L, 25L, 26L);

        NumbersArePositiveParams params = new NumbersArePositiveParams(
                values.size(),
                10
        );

        Truth.assertThat(testPositive(params, values)).isTrue();
    }

    @Test
    protected void testOneNegative() throws Exception {
        List<Long> values = List.of(16L, -17L, 1021L, 25L, 26L);

        NumbersArePositiveParams params = new NumbersArePositiveParams(
                values.size(),
                10
        );

        Truth.assertThat(testPositive(params, values)).isFalse();
    }


    @Test
    protected void testAllNegative() throws Exception {
        List<Long> values = List.of(-16L, -17L, -1021L, -25L, -26L);

        NumbersArePositiveParams params = new NumbersArePositiveParams(
                values.size(),
                10
        );

        Truth.assertThat(testPositive(params, values)).isFalse();
    }

    private boolean testPositive(NumbersArePositiveParams params, List<Long> values) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(GadgetType.numbers_are_positive, values, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(GadgetType.numbers_are_positive, params, proof2, pc, bg2);
    }
}
