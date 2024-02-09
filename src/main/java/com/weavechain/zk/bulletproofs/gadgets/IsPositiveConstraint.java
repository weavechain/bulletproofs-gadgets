package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.*;

import java.util.ArrayList;
import java.util.List;

public class IsPositiveConstraint {

    public static boolean verify(ConstraintSystem cs, Allocated variable, int bitsize) {
        List<Term> constraints = new ArrayList<>();

        constraints.add(new Term(variable.getVariable(), Utils.MINUS_ONE));

        Scalar exp2 = Scalar.ONE;
        for (int i = 0; i < bitsize; i++) {
            long bit = variable.getAssignment() != null && variable.getAssignment().testBit(i) ? 1L : 0L;
            LRO lro = cs.allocateMultiplier(Utils.scalar(1 - bit), Utils.scalar(bit));

            // Enforce a * b = 0, so one of (a,b) is zero
            cs.constrain(LinearCombination.from(lro.getOutput()));

            // Enforce that a = 1 - b, so they both are 1 or 0
            cs.constrain(LinearCombination.from(lro.getLeft()).add(LinearCombination.from(lro.getRight()).sub(LinearCombination.from(Scalar.ONE))));

            constraints.add(new Term(lro.getRight(), exp2));
            exp2 = exp2.add(exp2);
        }

        // Enforce that -v + Sum(b_i * 2^i, i = 0..n-1) = 0 => Sum(b_i * 2^i, i = 0..n-1) = v
        LinearCombination lc = null;
        for (Term t : constraints) {
            lc = lc == null ? LinearCombination.from(t) : lc.add(LinearCombination.from(t));
        }
        cs.constrain(lc);

        return true;
    }
}
