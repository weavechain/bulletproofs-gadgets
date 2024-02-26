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
public class NumberIsZero implements Gadget<NumberIsZeroParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberIsZero.class);

    private final GadgetType type = Gadgets.number_is_zero;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberIsZeroParams.class);
    }

    @Override
    public Proof generate(Object value, NumberIsZeroParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        BigInteger v = ConvertUtils.convertToBigInteger(value);

        List<ECPoint> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        if (checkZero(prover, av)) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberIsZeroParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        if (checkZero(verifier, av)) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkZero(ConstraintSystem verifier, Allocated x) {
        return IsZeroConstraint.verify(verifier, x);
    }
}
