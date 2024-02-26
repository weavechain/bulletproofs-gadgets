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
public class NumberIsPositive implements Gadget<NumberIsPositiveParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberIsPositive.class);

    private final GadgetType type = Gadgets.number_is_positive;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberIsPositiveParams.class);
    }

    @Override
    public Proof generate(Object value, NumberIsPositiveParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        BigInteger v = ConvertUtils.convertToBigInteger(value);
        Integer bitsize = params.getBitsize();

        List<ECPoint> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        if (checkPositive(prover, av, bitsize)) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberIsPositiveParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Integer bitsize = params.getBitsize();

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        if (checkPositive(verifier, av, bitsize)) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkPositive(ConstraintSystem verifier, Allocated v, Integer bitsize) {
        return IsPositiveConstraint.verify(verifier, v, bitsize);
    }
}
