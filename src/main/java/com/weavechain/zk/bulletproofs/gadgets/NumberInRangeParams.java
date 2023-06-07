package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class NumberInRangeParams extends GadgetParamsSerialized {

    private final Long min;

    private final Long max;

    private final Integer bitsize;
}
