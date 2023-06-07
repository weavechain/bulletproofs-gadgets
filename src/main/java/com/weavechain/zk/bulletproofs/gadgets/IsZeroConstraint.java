package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.Allocated;
import com.weavechain.zk.bulletproofs.ConstraintSystem;
import com.weavechain.zk.bulletproofs.LinearCombination;
import com.weavechain.zk.bulletproofs.Utils;

public class IsZeroConstraint {

    public static boolean verify(ConstraintSystem cs, Allocated x) {
        long y = 0L;
        long inv = 0L;

        LinearCombination x_lc = LinearCombination.from(x.getVariable());
        LinearCombination one_minus_y_lc = LinearCombination.from(Utils.scalar(1 - y));
        LinearCombination y_lc = LinearCombination.from(Utils.scalar(y));
        LinearCombination inv_lc = LinearCombination.from(Utils.scalar(inv));

        LinearCombination o1 = LinearCombination.from(cs.multiply(x_lc.clone(), one_minus_y_lc).getOutput());
        cs.constrain(o1);

        LinearCombination o2 = LinearCombination.from(cs.multiply(x_lc, inv_lc).getOutput());
        cs.constrain(o2.sub(y_lc));

        return true;
    }
}
