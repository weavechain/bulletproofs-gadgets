package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.Gadgets;
import com.weavechain.zk.bulletproofs.gadgets.NumberIsNotEqualParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class NumberIsNotEqualTest extends ZkTest {

    @Test
    protected void testNotEqual() throws Exception {
        NumberIsNotEqualParams params = new NumberIsNotEqualParams(123L);

        Long value = 128L;

        Truth.assertThat(testNotEqual(params, value)).isTrue();
    }

    @Test
    protected void testEqual() throws Exception {
        NumberIsNotEqualParams params = new NumberIsNotEqualParams(123L);

        Long value = 123L;

        Truth.assertThat(testNotEqual(params, value)).isFalse();
    }

    private boolean testNotEqual(NumberIsNotEqualParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(Gadgets.number_is_not_equal, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(Gadgets.number_is_not_equal, params, proof2, pc, bg2);
    }
}
