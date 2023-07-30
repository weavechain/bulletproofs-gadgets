package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.GadgetType;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class GadgetImpl implements GadgetType {

    private final String name;

    public String name() {
        return name;
    }
}