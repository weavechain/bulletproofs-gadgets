package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.curve25519.CompressedRistretto;
import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.*;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

@Getter
public class NumbersSumTo implements Gadget<NumbersSumToParams> {

    static final Logger logger = LoggerFactory.getLogger(NumbersSumTo.class);

    private final GadgetType type = Gadgets.numbers_sum_to;

    private final boolean batchProof = true;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumbersSumToParams.class);
    }

    @Override
    public Proof generate(Object value, NumbersSumToParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        List<Long> values = ConvertUtils.convertToLongList(value);

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Long sum = 0L;
        List<LinearCombination> sums = new ArrayList<>();
        for (Long v : values) {
            Commitment leftComm = prover.commit(Utils.scalar(sum), rnd != null ? rnd : Utils.randomScalar());
            Allocated aleft = new Allocated(leftComm.getVariable(), sum);
            commitments.add(leftComm.getCommitment());

            Commitment rightComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
            Allocated aright = new Allocated(rightComm.getVariable(), v);
            commitments.add(rightComm.getCommitment());

            LinearCombination next = LinearCombination.from(aleft.getVariable()).clone().add(LinearCombination.from(aright.getVariable()));
            sums.add(next);

            sum += v;
        }
        prover.constrainLCWithScalar(sums.get(sums.size() - 1), Utils.scalar(sum));

        Commitment vComm = prover.commit(Utils.scalar(sum), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), sum);
        commitments.add(vComm.getCommitment());

        Scalar diff = Utils.scalar(params.getExpected()).subtract(Utils.scalar(sum));
        Commitment diffComm = prover.commit(diff, Utils.randomScalar());
        Allocated adiff = new Allocated(diffComm.getVariable(), Utils.scalarToLong(diff));
        commitments.add(diffComm.getCommitment());

        if (checkEqual(prover, av, adiff, values.size(), params.getExpected(), params.getBitsize())) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumbersSumToParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        List<LinearCombination> sums = buildSums(verifier, proof, params.getCount());
        verifier.constrainLCWithScalar(sums.get(sums.size() - 1), Utils.scalar(params.getExpected()));

        Variable v = verifier.commit(proof.getCommitment(sums.size() * 2));
        Allocated av = new Allocated(v, null);

        Variable vdiff = verifier.commit(proof.getCommitment(sums.size() * 2 + 1));
        Allocated adiff = new Allocated(vdiff, null);

        if (checkEqual(verifier, av, adiff, sums.size(), params.getExpected(), params.getBitsize())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    private List<LinearCombination> buildSums(Verifier verifier, Proof proof, int count) {
        List<LinearCombination> sums = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            Variable sum = verifier.commit(proof.getCommitment(i * 2));
            Allocated asum = new Allocated(sum, null);

            Variable val = verifier.commit(proof.getCommitment(i * 2 + 1));
            Allocated aval = new Allocated(val, null);

            LinearCombination next = LinearCombination.from(asum.getVariable()).clone().add(LinearCombination.from(aval.getVariable()));
            sums.add(next);
        }

        return sums;
    }

    public boolean checkEqual(ConstraintSystem verifier, Allocated v, Allocated diff, int count, Long expected, int bitsize) {
        if (count == 0) {
            return expected == 0;
        } else {
            LinearCombination product = LinearCombination.from(Variable.ONE);

            verifier.constrainLCWithScalar(LinearCombination.from(diff.getVariable()).add(LinearCombination.from(v.getVariable())), Utils.scalar(expected));

            Variable o1 = verifier.multiply(product, LinearCombination.from(diff.getVariable())).getOutput();
            product = LinearCombination.from(o1);

            verifier.constrain(product);

            return IsPositiveConstraint.verify(verifier, v, bitsize);
        }
    }
}

