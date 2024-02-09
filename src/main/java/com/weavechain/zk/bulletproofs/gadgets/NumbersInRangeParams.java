package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.math.BigInteger;

@Getter
@AllArgsConstructor
public class NumbersInRangeParams extends GadgetParamsSerialized {

    private final Integer count;

    private final BigInteger min;

    private final BigInteger max;

    private final Integer bitsize;

    public NumbersInRangeParams(Integer count, long min, long max, Integer bitsize) {
        this(count, BigInteger.valueOf(min), BigInteger.valueOf(max), bitsize);
    }
}
