package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.NumberNotInListParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class NumberNotInListTest extends ZkTest {

    @Test
    protected void testNotInList() throws Exception {
        NumberNotInListParams params = new NumberNotInListParams(List.of(1L, 3L, 128L, 145L), 8);

        Long value = 5L;

        Truth.assertThat(testNotInList(params, value)).isTrue();
    }

    @Test
    protected void testInList() throws Exception {
        NumberNotInListParams params = new NumberNotInListParams(List.of(1L, 3L, 128L, 145L), 8);

        Long value = 128L;

        Truth.assertThat(testNotInList(params, value)).isFalse();
    }

    private boolean testNotInList(NumberNotInListParams params, Long value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);
        Proof proof = bulletProofs.generate(GadgetType.number_not_in_list, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);
        return bulletProofs.verify(GadgetType.number_not_in_list, params, proof2, pc, bg2);
    }
}
