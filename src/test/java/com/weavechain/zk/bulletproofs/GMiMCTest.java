package com.weavechain.zk.bulletproofs;

import com.google.common.truth.Truth;
import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.gadgets.*;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

public class GMiMCTest extends ZkTest {

    @Test
    protected void testHash() {
        int seed = 1234;
        int rounds = MiMC.DEFAULT_MIMC_ROUNDS;

        GMiMC gmimc = new GMiMC(3, 5, seed, rounds);
        int TEST_RUNS = 5;

        int t = gmimc.getStateSize();

        for (int i = 0; i < TEST_RUNS; i++) {
            List<Scalar> input1 = new ArrayList<>();
            for (int j = 0; j < t; j++) {
                input1.add(Utils.randomScalar());
            }

            List<Scalar> input2 = new ArrayList<>();
            do {
                for (int j = 0; j < t; j++) {
                    input2.add(Utils.randomScalar());
                }
            } while (input1.equals(input2));

            List<Scalar> perm1 = gmimc.permute(input1);
            List<Scalar> perm2 = gmimc.permute(input1);
            List<Scalar> perm3 = gmimc.permute(input2);

            for (int j = 0; j < t; j++) {
                Truth.assertThat(perm1.get(j)).isEqualTo(perm2.get(j));
                Truth.assertThat(perm1.get(j)).isNotEqualTo(perm3.get(j));
            }
        }
    }

    @Test
    protected void testPerf() {
        int seed = 1234;
        int rounds = MiMC.DEFAULT_MIMC_ROUNDS;
        int size = 16;
        int degree = 3;

        for (int i = 0; i < 100; i++) {
            Scalar l = Utils.randomScalar();
            Scalar r = Utils.randomScalar();
            Scalar h1 = MiMC.mimc(l, r, seed, rounds);
            Scalar h2 = GMiMC.gmimc(l, r, size, degree, seed, rounds);
        }

        long tm = 0;
        long tg = 0;

        for (int i = 0; i < 10000; i++) {
            Scalar l = Utils.randomScalar();
            Scalar r = Utils.randomScalar();

            long start = System.currentTimeMillis();
            Scalar h1 = MiMC.mimc(l, r, seed, rounds);
            long end = System.currentTimeMillis();
            tm += end - start;

            start = System.currentTimeMillis();
            Scalar h2 = GMiMC.gmimc(l, r, size, degree, seed, rounds);
            end = System.currentTimeMillis();
            tg += end - start;
        }

        System.out.println("MiMC (ms): " + tm);
        System.out.println("GMiMC (ms): " + tg);
    }
}
