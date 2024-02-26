package com.weavechain.zk.bulletproofs.gadgets;

import java.util.ArrayList;
import java.util.List;

import com.weavechain.ec.Scalar;
import com.weavechain.zk.bulletproofs.BulletProofs;
import lombok.Getter;

public class GMiMC {

    @Getter
    private final int stateSize;

    @Getter
    private final int degree;

    @Getter
    private final long seed;

    @Getter
    private final int rounds;

    private final List<Scalar> constants;

    public GMiMC(int stateSize, int degree, long seed, int rounds) {
        this.stateSize = stateSize;
        this.degree = degree;
        this.seed = seed;
        this.rounds = rounds;

        constants = MiMC.getConstants(seed, rounds);
    }

    public static Scalar gmimc(Scalar left, Scalar right, int stateSize, int degree, long seed, int rounds) {
        GMiMC hash = new GMiMC(stateSize, degree, seed, rounds);

        List<Scalar> items = new ArrayList<>();
        items.add(left);
        items.add(right);
        for (int i = 0; i < stateSize - 2; i++) {
            items.add(BulletProofs.getFactory().zero());
        }

        List<Scalar> result = hash.permute(items);
        return result.get(0);
    }

    private void round(List<Scalar> state, int round) {
        Scalar power = sbox(state.get(0), round);
        for (int i = 1; i < state.size(); i++) {
            state.set(i,  state.get(i).add(power));
        }
    }

    private Scalar sbox(Scalar state, int round) {
        Scalar input = state.add(constants.get(round));

        Scalar input2 = input.square();
        switch (degree) {
            case 3:
                return input2.multiply(input);
            case 5:
                return input2.square().multiply(input);
            case 7:
                return input2.square().multiply(input2).multiply(input);
            default:
                throw new IllegalArgumentException("Invalid value");
        }
    }

    public List<Scalar> permute(List<Scalar> input) {
        if (this.stateSize != input.size()) {
            throw new IllegalArgumentException("Invalid input length");
        }
        
        if (this.stateSize < 8) {
            List<Scalar> state = new ArrayList<>(input);
            for (int r = 0; r < rounds - 1; r++) {
                round(state, r);
                state.add(1, BulletProofs.getFactory().zero());
                state.remove(state.size() - 1);
            }

            round(state, rounds - 1);

            return state;
        }

        List<Scalar> state = new ArrayList<>(input);
        Scalar acc = BulletProofs.getFactory().zero();
        List<Scalar> items = new ArrayList<>(this.stateSize - 1);
        for (int r = 0; r < rounds - 1; r++) {
            Scalar power = sbox(state.get(0), r);
            items.add(0, power);
            acc = acc.subtract(items.get(items.size() - 1));
            acc = acc.add(power);

            state.add(1, BulletProofs.getFactory().zero());
            state.remove(state.size() - 1);

            state.set(0, state.get(0).add(acc));
        }

        Scalar power = sbox(state.get(0), rounds - 1);
        items.add(0, power);
        acc = acc.subtract(items.get(items.size() - 1));
        acc = acc.add(power);
        state.set(this.stateSize - 1, state.get(this.stateSize - 1).add(acc));

        for (int i = 1; i < this.stateSize - 1; i++) {
            items.add(0, power);
            acc = acc.subtract(items.get(items.size() - 1));
            state.set(this.stateSize - 1 - i, state.get(this.stateSize - 1 - i).add(acc));
        }

        return state;
    }
}
