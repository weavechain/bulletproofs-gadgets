package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class NumberNotInListParams extends GadgetParamsSerialized {

    private final List<Long> list;

    private final Integer bitsize;
}
