package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumbersSumToParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class NumbersSumToTest extends ZkTest {

    @Test
    protected void testSum() throws Exception {
        NumbersSumToParams params = new NumbersSumToParams(10L, 4, 10);

        List<Long> values = List.of(1L, 2L, 3L, 4L);

        Truth.assertThat(testSumEquals(params, values)).isTrue();
    }

    @Test
    protected void testSum2() throws Exception {
        NumbersSumToParams params = new NumbersSumToParams(101015L, 7, 20);

        List<Long> values = List.of(1L, 2L, 3L, 4L, 5L, 1000L, 100000L);

        Truth.assertThat(testSumEquals(params, values)).isTrue();
    }

    @Test
    protected void testSum3() throws Exception {
        NumbersSumToParams params = new NumbersSumToParams(83L, 6, 20);

        List<Long> values = List.of(10L, 25L, 11L, 2L, 20L, 15L);

        Truth.assertThat(testSumEquals(params, values)).isTrue();
    }

    @Test
    protected void testSumFail() throws Exception {
        NumbersSumToParams params = new NumbersSumToParams(15L, 7, 20);

        List<Long> values = List.of(1L, 2L, 3L, 4L, 5L, 1000L, 100000L);

        Truth.assertThat(testSumEquals(params, values)).isFalse();
    }

    @Test
    protected void testSumCountFail() throws Exception {
        NumbersSumToParams params = new NumbersSumToParams(101015L, 6, 20);

        List<Long> values = List.of(1L, 2L, 3L, 4L, 5L, 1000L, 100000L);

        Truth.assertThat(testSumEquals(params, values)).isFalse();
    }

    private boolean testSumEquals(NumbersSumToParams params, List<Long> values) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(GadgetType.numbers_sum_to, values, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(GadgetType.numbers_sum_to, params, proof2, pc, bg2);
    }
}
