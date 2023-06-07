package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.Allocated;
import com.weavechain.zk.bulletproofs.ConstraintSystem;
import com.weavechain.zk.bulletproofs.LinearCombination;
import com.weavechain.zk.bulletproofs.Utils;

public class IsEqualsConstraint {

    public static boolean verify(ConstraintSystem cs, Allocated x, Long expected) {
        LinearCombination x_lc = LinearCombination.from(x.getVariable());
        LinearCombination one_minus_y_lc = LinearCombination.from(Utils.scalar(1 - expected));
        LinearCombination y_lc = LinearCombination.from(Utils.scalar(expected));
        LinearCombination inv_lc = LinearCombination.from(Utils.scalar(expected).invert());

        LinearCombination o1 = LinearCombination.from(cs.multiply(x_lc.clone(), one_minus_y_lc).getOutput());
        cs.constrain(o1);

        LinearCombination o2 = LinearCombination.from(cs.multiply(x_lc, inv_lc).getOutput());
        cs.constrain(o2.sub(y_lc));

        return true;
    }
}
