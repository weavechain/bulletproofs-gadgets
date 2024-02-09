package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.math.BigInteger;

@Getter
@AllArgsConstructor
public class NumberInRangeParams extends GadgetParamsSerialized {

    private final BigInteger min;

    private final BigInteger max;

    private final Integer bitsize;

    public NumberInRangeParams(long min, long max, Integer bitsize) {
        this(BigInteger.valueOf(min), BigInteger.valueOf(max), bitsize);
    }
}
