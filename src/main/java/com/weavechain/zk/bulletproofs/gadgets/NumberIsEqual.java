package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.curve25519.CompressedRistretto;
import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.*;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

@Getter
public class NumberIsEqual implements Gadget<NumberIsEqualParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberIsEqual.class);

    private final GadgetType type = Gadgets.number_is_equal;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberIsEqualParams.class);
    }

    @Override
    public Proof generate(Object value, NumberIsEqualParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        BigInteger v = ConvertUtils.convertToBigInteger(value);

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        Scalar diff = Utils.scalar(params.getExpected()).subtract(Utils.scalar(v));
        Commitment diffComm = prover.commit(diff, Utils.randomScalar());
        Allocated adiff = new Allocated(diffComm.getVariable(), Utils.toBigInteger(diff));
        commitments.add(diffComm.getCommitment());

        if (checkEqual(prover, av, adiff, params.getExpected(), params.getBitsize())) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberIsEqualParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        Variable diff = verifier.commit(proof.getCommitment(1));
        Allocated adiff = new Allocated(diff, null);

        if (checkEqual(verifier, av, adiff, params.getExpected(), params.getBitsize())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkEqual(ConstraintSystem verifier, Allocated v, Allocated diff, Long expected, int bitsize) {
        LinearCombination product = LinearCombination.from(Variable.ONE);

        verifier.constrainLCWithScalar(LinearCombination.from(diff.getVariable()).add(LinearCombination.from(v.getVariable())), Utils.scalar(expected));

        Variable o1 = verifier.multiply(product, LinearCombination.from(diff.getVariable())).getOutput();
        product = LinearCombination.from(o1);

        verifier.constrain(product);

        return IsPositiveConstraint.verify(verifier, v, bitsize);
    }
}
