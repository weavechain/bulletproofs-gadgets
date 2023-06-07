package com.weavechain.zk.bulletproofs;

import com.weavechain.zk.bulletproofs.gadgets.Gadgets;

public class ZkTest  {

    protected final BulletProofs bulletProofs = createProofs();

    public static BulletProofs createProofs() {
        final BulletProofs bulletProofs = new BulletProofs();

        Gadgets.registerGadgets(bulletProofs);

        return bulletProofs;
    }
}
