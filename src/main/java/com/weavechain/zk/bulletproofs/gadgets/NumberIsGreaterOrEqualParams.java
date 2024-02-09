package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.math.BigInteger;

@Getter
@AllArgsConstructor
public class NumberIsGreaterOrEqualParams extends GadgetParamsSerialized {

    private final transient BigInteger min;

    private final Integer bitsize;

    public NumberIsGreaterOrEqualParams(long min, Integer bitsize) {
        this(BigInteger.valueOf(min), bitsize);
    }
}
