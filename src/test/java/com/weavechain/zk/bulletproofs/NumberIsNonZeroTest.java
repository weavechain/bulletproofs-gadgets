package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.Gadgets;
import com.weavechain.zk.bulletproofs.gadgets.NumberIsNonZeroParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class NumberIsNonZeroTest extends ZkTest {

    @Test
    protected void testNonZero() throws Exception {
        NumberIsNonZeroParams params = new NumberIsNonZeroParams();

        Long value = 128L;

        Truth.assertThat(testNonZero(params, value)).isTrue();
    }

    @Test
    protected void testZero() throws Exception {
        NumberIsNonZeroParams params = new NumberIsNonZeroParams();

        Long value = 0L;

        Truth.assertThat(testNonZero(params, value)).isFalse();
    }

    private boolean testNonZero(NumberIsNonZeroParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(Gadgets.number_is_non_zero, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(Gadgets.number_is_non_zero, params, proof2, pc, bg2);
    }
}
