package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.Gadgets;
import com.weavechain.zk.bulletproofs.gadgets.NumberIsZeroParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class NumberIsZeroTest extends ZkTest {

    @Test
    protected void testZero() throws Exception {
        NumberIsZeroParams params = new NumberIsZeroParams();

        Long value = 0L;

        Truth.assertThat(testZero(params, value)).isTrue();
    }

    @Test
    protected void testNonZero() throws Exception {
        NumberIsZeroParams params = new NumberIsZeroParams();

        Long value = 1L;

        Truth.assertThat(testZero(params, value)).isFalse();
    }

    private boolean testZero(NumberIsZeroParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(Gadgets.number_is_zero, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(Gadgets.number_is_zero, params, proof2, pc, bg2);
    }
}
