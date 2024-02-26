package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.Gadgets;
import com.weavechain.zk.bulletproofs.gadgets.NumberIsEqualParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class NumberIsEqualTest extends ZkTest {

    @Test
    protected void testEqual() throws Exception {
        NumberIsEqualParams params = new NumberIsEqualParams(4L, 8);

        Long value = 4L;

        Truth.assertThat(testEqual(params, value)).isTrue();
    }

    @Test
    protected void testNonEqual() throws Exception {
        NumberIsEqualParams params = new NumberIsEqualParams(4L, 8);

        Long value = 1L;

        Truth.assertThat(testEqual(params, value)).isFalse();
    }

    private boolean testEqual(NumberIsEqualParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(Gadgets.number_is_equal, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(Gadgets.number_is_equal, params, proof2, pc, bg2);
    }
}
