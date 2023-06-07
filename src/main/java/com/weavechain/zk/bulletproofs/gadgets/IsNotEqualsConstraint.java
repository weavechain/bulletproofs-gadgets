package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.Allocated;
import com.weavechain.zk.bulletproofs.ConstraintSystem;
import com.weavechain.zk.bulletproofs.LinearCombination;
import com.weavechain.zk.bulletproofs.Utils;

public class IsNotEqualsConstraint {

    public static boolean verify(ConstraintSystem cs, Allocated v, Allocated diff, Allocated diffinv, Long expected) {

        cs.constrainLCWithScalar(LinearCombination.from(diff.getVariable()).add(LinearCombination.from(v.getVariable())), Utils.scalar(expected));

        return IsNonZeroConstraint.verify(cs, diff, diffinv);
    }
}
