package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.ec.ECPoint;
import com.weavechain.ec.Scalar;
import com.weavechain.zk.bulletproofs.*;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
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
        List<BigInteger> values = ConvertUtils.convertToBigIntegerList(value);

        List<ECPoint> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        BigInteger sum = BigInteger.ZERO;
        LinearCombination next = null;
        for (BigInteger v : values) {
            Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
            commitments.add(vComm.getCommitment());

            next = next != null ? next.add(LinearCombination.from(vComm.getVariable())) : LinearCombination.from(vComm.getVariable());
            sum = sum.add(v);
        }
        prover.constrainLCWithScalar(next, Utils.scalar(sum));

        Commitment vComm = prover.commit(Utils.scalar(sum), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), sum);
        commitments.add(vComm.getCommitment());

        Scalar diff = Utils.scalar(params.getExpected()).subtract(Utils.scalar(sum));
        Commitment diffComm = prover.commit(diff, Utils.randomScalar());
        commitments.add(diffComm.getCommitment());

        if (checkEqual(prover, av, diffComm.getVariable(), values.size(), params.getExpected(), params.getBitsize())) {
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

        LinearCombination sum = buildSum(verifier, proof, params.getCount());
        verifier.constrainLCWithScalar(sum, Utils.scalar(params.getExpected()));

        Variable v = verifier.commit(proof.getCommitment(params.getCount()));
        Allocated av = new Allocated(v, null);

        Variable vdiff = verifier.commit(proof.getCommitment(params.getCount() + 1));

        if (checkEqual(verifier, av, vdiff, params.getCount(), params.getExpected(), params.getBitsize())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    private LinearCombination buildSum(Verifier verifier, Proof proof, int count) {
        LinearCombination next = null;
        for (int i = 0; i < count; i++) {
            Variable val = verifier.commit(proof.getCommitment(i));

            next = next != null ? next.add(LinearCombination.from(val)) : LinearCombination.from(val);
        }

        return next;
    }

    public boolean checkEqual(ConstraintSystem verifier, Allocated v, Variable diff, int count, Long expected, int bitsize) {
        if (count == 0) {
            return expected == 0;
        } else {
            LinearCombination product = LinearCombination.from(Variable.ONE);

            verifier.constrainLCWithScalar(LinearCombination.from(diff).add(LinearCombination.from(v.getVariable())), Utils.scalar(expected));

            Variable o1 = verifier.multiply(product, LinearCombination.from(diff)).getOutput();
            product = LinearCombination.from(o1);

            verifier.constrain(product);

            return IsPositiveConstraint.verify(verifier, v, bitsize);
        }
    }
}

