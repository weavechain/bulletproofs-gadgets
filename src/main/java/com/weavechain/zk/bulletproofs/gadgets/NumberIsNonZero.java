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
public class NumberIsNonZero implements Gadget<NumberIsNonZeroParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberIsNonZero.class);

    private final GadgetType type = Gadgets.number_is_non_zero;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberIsNonZeroParams.class);
    }

    @Override
    public Proof generate(Object value, NumberIsNonZeroParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        BigInteger v = ConvertUtils.convertToBigInteger(value);

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        Scalar ainv = Utils.scalar(v).invert();
        Commitment ainvComm = prover.commit(ainv, Utils.randomScalar());
        Allocated avinv = new Allocated(ainvComm.getVariable(), Utils.toBigInteger(ainv));
        commitments.add(ainvComm.getCommitment());

        if (checkNonZero(prover, av, avinv)) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberIsNonZeroParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        Variable vinv = verifier.commit(proof.getCommitment(1));
        Allocated ainv = new Allocated(vinv, null);

        if (checkNonZero(verifier, av, ainv)) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkNonZero(ConstraintSystem verifier, Allocated x, Allocated xinv) {
        return IsNonZeroConstraint.verify(verifier, x, xinv);
    }
}
