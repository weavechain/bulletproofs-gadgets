package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class NumberIsGreaterOrEqualParams extends GadgetParamsSerialized {

    private final transient Long min;

    private final Integer bitsize;
}
