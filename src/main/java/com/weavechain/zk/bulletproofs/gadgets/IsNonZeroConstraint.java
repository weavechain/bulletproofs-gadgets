package com.weavechain.zk.bulletproofs.gadgets;

import cafe.cryptography.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.Allocated;
import com.weavechain.zk.bulletproofs.ConstraintSystem;
import com.weavechain.zk.bulletproofs.LinearCombination;
import com.weavechain.zk.bulletproofs.Variable;

public class IsNonZeroConstraint {

    public static boolean verify(ConstraintSystem cs, Allocated x, Allocated xinv) {
        LinearCombination x_lc = LinearCombination.from(x.getVariable());
        LinearCombination y_lc = LinearCombination.from(Scalar.ONE);

        LinearCombination o1 = LinearCombination.from(cs.multiply(x_lc.clone(), LinearCombination.from(Variable.ONE).sub(y_lc.clone())).getOutput());
        cs.constrain(o1);

        LinearCombination inv_lc = LinearCombination.from(xinv.getVariable());
        LinearCombination o2 = LinearCombination.from(cs.multiply(x_lc.clone(), inv_lc.clone()).getOutput());
        cs.constrain(o2.sub(y_lc));

        return true;
    }
}
