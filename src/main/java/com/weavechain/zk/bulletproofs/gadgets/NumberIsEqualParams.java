package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class NumberIsEqualParams extends GadgetParamsSerialized {

    private final transient Long expected;

    private final Integer bitsize;
}
