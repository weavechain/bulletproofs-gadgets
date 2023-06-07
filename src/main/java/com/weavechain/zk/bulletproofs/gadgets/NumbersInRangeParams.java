package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class NumbersInRangeParams extends GadgetParamsSerialized {

    private final Integer count;

    private final Long min;

    private final Long max;

    private final Integer bitsize;
}
