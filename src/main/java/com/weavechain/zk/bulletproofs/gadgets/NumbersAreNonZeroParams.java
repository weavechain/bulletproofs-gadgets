package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class NumbersAreNonZeroParams extends GadgetParamsSerialized {

    private final Integer count;
}
