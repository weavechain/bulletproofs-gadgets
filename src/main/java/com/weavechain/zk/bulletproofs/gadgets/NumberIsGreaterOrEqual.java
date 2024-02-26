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
public class NumberIsGreaterOrEqual implements Gadget<NumberIsGreaterOrEqualParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberIsGreaterOrEqual.class);

    private final GadgetType type = Gadgets.number_is_greater_or_equal;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberIsGreaterOrEqualParams.class);
    }

    @Override
    public Proof generate(Object value, NumberIsGreaterOrEqualParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        BigInteger v = ConvertUtils.convertToBigInteger(value);
        Integer bitsize = params.getBitsize();

        BigInteger a = v.subtract(params.getMin());

        List<ECPoint> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        Commitment aComm = prover.commit(Utils.scalar(a), Utils.randomScalar());
        Allocated aa = new Allocated(aComm.getVariable(), a);
        commitments.add(aComm.getCommitment());

        if (checkGreater(prover, av, aa, params.getMin(), bitsize)) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberIsGreaterOrEqualParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        Variable a = verifier.commit(proof.getCommitment(1));
        Allocated aa = new Allocated(a, null);

        if (checkGreater(verifier, av, aa, params.getMin(), params.getBitsize())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkGreater(ConstraintSystem cs, Allocated v, Allocated a, BigInteger min, Integer bitsize) {
        cs.constrain(LinearCombination.from(v.getVariable()).sub(LinearCombination.from(Utils.scalar(min))).sub(LinearCombination.from(a.getVariable())));

        return IsPositiveConstraint.verify(cs, a, bitsize);
    }
}
