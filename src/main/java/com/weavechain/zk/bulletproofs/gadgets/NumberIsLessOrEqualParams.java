package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.math.BigInteger;

@Getter
@AllArgsConstructor
public class NumberIsLessOrEqualParams extends GadgetParamsSerialized {

    private final transient BigInteger max;

    private final Integer bitsize;

    public NumberIsLessOrEqualParams(long max, Integer bitsize) {
        this(BigInteger.valueOf(max), bitsize);
    }
}
