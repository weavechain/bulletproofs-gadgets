package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class RecordsAddPreImageHashParams extends GadgetParamsSerialized {

    private final transient String expectedHash;

    private final transient String fromHash;

    //can be replaced with row hash + row serialization length
    private final transient List<Object> newRow;

    private int rounds = MiMC.DEFAULT_MIMC_ROUNDS;

    private long seed = 0; //seed works only as long as the RNG is the same, otherwise the prover and the verifier need to share the constants
}
