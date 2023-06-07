package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetParamsSerialized;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class RecordsWithHashesSumToParams extends GadgetParamsSerialized {

    private final transient Long expected;

    private final Integer count;

    private final Integer bitsize;

    private final String salt;

    private final transient List<String> hashes;

    private final Integer sumColumnIndex;
}
