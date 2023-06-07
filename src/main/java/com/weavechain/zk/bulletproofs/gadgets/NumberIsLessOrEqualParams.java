package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class NumberIsLessOrEqualParams extends GadgetParamsSerialized {

    private final transient Long max;

    private final Integer bitsize;
}
