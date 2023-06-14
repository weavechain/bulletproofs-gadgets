package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.ConstraintSystem;
import com.weavechain.zk.bulletproofs.LRO;
import com.weavechain.zk.bulletproofs.LinearCombination;
import com.weavechain.zk.bulletproofs.Variable;

import java.util.List;

public class MiMCHash {

    public static LinearCombination mimc(ConstraintSystem cs, LinearCombination left, LinearCombination right, long seed, int rounds) {
        LinearCombination xl = left;
        LinearCombination xr = right;

        List<Scalar> constants = MiMC.getConstants(seed, rounds);

        for (int i = 0; i < rounds; i++) {
            LinearCombination const_lc = LinearCombination.from(constants.get(i));

            LinearCombination tmp1 = xl.clone().add(const_lc);

            LRO mul = cs.multiply(tmp1.clone(), tmp1);
            Variable sq = mul.getOutput();
            Variable cube = cs.multiply(LinearCombination.from(sq), LinearCombination.from(mul.getLeft())).getOutput();
            LinearCombination tmp2 = LinearCombination.from(cube).add(xr);

            xr = xl;
            xl = tmp2;
        }

        return xl;
    }
}
