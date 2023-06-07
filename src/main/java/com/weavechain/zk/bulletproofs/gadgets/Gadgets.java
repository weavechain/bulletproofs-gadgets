package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.BulletProofs;

public class Gadgets {

    //Some gadgets based on https://github.com/lovesh/bulletproofs-r1cs-gadgets
    //  see LICENSE-orig.txt

    public static void registerGadgets(BulletProofs bulletProofs) {
        bulletProofs.registerGadget(new NumberInRange());
        bulletProofs.registerGadget(new NumbersInRange());
        bulletProofs.registerGadget(new NumberIsPositive());
        bulletProofs.registerGadget(new NumbersArePositive());
        bulletProofs.registerGadget(new NumbersSumTo());
        bulletProofs.registerGadget(new RecordsWithHashesSumTo());
        bulletProofs.registerGadget(new RecordsWithHashPreImageSumTo());
        bulletProofs.registerGadget(new RecordsAddUpdateProof());
        bulletProofs.registerGadget(new NumberIsNonZero());
        bulletProofs.registerGadget(new NumbersAreNonZero());
        bulletProofs.registerGadget(new NumberIsZero());
        bulletProofs.registerGadget(new NumberIsNotEqual());
        bulletProofs.registerGadget(new NumberIsEqual());
        bulletProofs.registerGadget(new NumberInList());
        bulletProofs.registerGadget(new NumberNotInList());
        bulletProofs.registerGadget(new NumberIsGreaterOrEqual());
        bulletProofs.registerGadget(new NumberIsLessOrEqual());
        bulletProofs.registerGadget(new MiMCHashPreImage());
        bulletProofs.registerGadget(new MiMCStringHashPreImage());
    }
}