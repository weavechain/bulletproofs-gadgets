package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

@Getter
@AllArgsConstructor
public class MiMCStringHashPreImageParams extends GadgetParamsSerialized {

    private int rounds = MiMC.DEFAULT_MIMC_ROUNDS;

    private long seed = 0; //seed works only as long as the RNG is the same, otherwise the prover and the verifier need to share the constants

    private final transient Scalar hash;

    private final Integer length;

    public MiMCStringHashPreImageParams(Scalar hash, Integer length, long seed) {
        this.hash = hash;
        this.length = length;
        this.seed = seed;
    }

    public static MiMCStringHashPreImageParams from(String data, long seed, int rounds) {
        AtomicInteger depth = new AtomicInteger(0);
        AtomicInteger length = new AtomicInteger(0);
        Scalar hash = MiMC.mimcHash(data.getBytes(StandardCharsets.UTF_8), seed, rounds, depth, length, MiMCStringHashPreImage.useZstdCompress);
        return new MiMCStringHashPreImageParams(rounds, seed, hash, length.get());
    }
}
