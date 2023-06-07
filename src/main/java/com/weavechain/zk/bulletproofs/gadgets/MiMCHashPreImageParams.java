package com.weavechain.zk.bulletproofs.gadgets;

import cafe.cryptography.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import com.weavechain.zk.bulletproofs.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class MiMCHashPreImageParams extends GadgetParamsSerialized {

    private int rounds = MiMC.DEFAULT_MIMC_ROUNDS;

    private long seed = 0; //seed works only as long as the RNG is the same, otherwise the prover and the verifier need to share the constants

    private final transient Scalar hash;

    public MiMCHashPreImageParams(Scalar hash, long seed) {
        this.hash = hash;
        this.seed = seed;
    }

    public static MiMCHashPreImageParams from(Scalar left, Scalar right, long seed, int rounds) {
        return new MiMCHashPreImageParams(rounds, seed, computeHash(left, right, seed, rounds));
    }

    public static MiMCHashPreImageParams from(Long left, Long right, long seed, int rounds) {
        return new MiMCHashPreImageParams(rounds, seed, computeHash(Utils.scalar(left), Utils.scalar(right), seed, rounds));
    }

    public static Scalar computeHash(Scalar left, Scalar right, long seed, int rounds) {
        return MiMC.mimc(left, right, seed, rounds);
    }
}
