package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class RecordsWithHashPreImageSumToParams extends GadgetParamsSerialized {

    private final transient Long expected;

    private final Integer count;

    private final Integer bitsize;

    private final String salt;

    private final transient List<String> hashes;

    private final Integer sumColumnIndex;

    private int rounds = MiMC.DEFAULT_MIMC_ROUNDS;

    private long seed = 0; //seed works only as long as the RNG is the same, otherwise the prover and the verifier need to share the constants
}
