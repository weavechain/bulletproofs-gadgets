package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import com.google.common.truth.Truth;
import com.weavechain.zk.bulletproofs.gadgets.MiMC;
import com.weavechain.zk.bulletproofs.gadgets.MiMCHashPreImageParams;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class MiMCHashPreimageTest extends ZkTest {

    @Test
    protected void testMatch() throws Exception {
        MiMCHashPreImageParams params = MiMCHashPreImageParams.from(1L, 0L, 0, MiMC.DEFAULT_MIMC_ROUNDS);

        List<Long> value = List.of(1L, 0L);

        Truth.assertThat(testMatch(params, value)).isTrue();
    }

    @Test
    protected void testNotMatch() throws Exception {
        MiMCHashPreImageParams params = MiMCHashPreImageParams.from(1L, 0L, 0, MiMC.DEFAULT_MIMC_ROUNDS);

        List<Long> value = List.of(1L, 2L);

        Truth.assertThat(testMatch(params, value)).isFalse();
    }

    private boolean testMatch(MiMCHashPreImageParams params, List<Long> value) throws NoSuchAlgorithmException, IOException {
        PedersenCommitment pc = PedersenCommitment.getDefault();

        Scalar rnd = Utils.randomScalar();
        BulletProofGenerators bg1 = new BulletProofGenerators(1024, 1);
        Proof proof = bulletProofs.generate(GadgetType.mimc_hash_preimage, value, params, rnd, pc, bg1);

        Proof proof2 = Proof.deserialize(proof.serialize());

        BulletProofGenerators bg2 = new BulletProofGenerators(1024, 1);
        return bulletProofs.verify(GadgetType.mimc_hash_preimage, params, proof2, pc, bg2);
    }
}
