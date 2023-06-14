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
public class NumberIsNotEqual implements Gadget<NumberIsNotEqualParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberIsNotEqual.class);

    private final GadgetType type = GadgetType.number_is_not_equal;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberIsNotEqualParams.class);
    }

    @Override
    public Proof generate(Object value, NumberIsNotEqualParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Long v = ConvertUtils.convertToLong(value);

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        Scalar diff = Utils.scalar(params.getExpected()).subtract(Utils.scalar(v));
        Commitment diffComm = prover.commit(diff, Utils.randomScalar());
        Allocated adiff = new Allocated(diffComm.getVariable(), Utils.scalarToLong(diff));
        commitments.add(diffComm.getCommitment());

        Scalar diffinv = diff.invert();
        Commitment diffinvComm = prover.commit(diffinv, Utils.randomScalar());
        Allocated adiffinv = new Allocated(diffinvComm.getVariable(), Utils.scalarToLong(diffinv));
        commitments.add(diffinvComm.getCommitment());

        if (checkNotEqual(prover, av, adiff, adiffinv, params.getExpected())) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberIsNotEqualParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        Variable diff = verifier.commit(proof.getCommitment(1));
        Allocated adiff = new Allocated(diff, null);

        Variable diffinv = verifier.commit(proof.getCommitment(2));
        Allocated adiffinv = new Allocated(diffinv, null);

        if (checkNotEqual(verifier, av, adiff, adiffinv, params.getExpected())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkNotEqual(ConstraintSystem verifier, Allocated v, Allocated diff, Allocated diffinv, Long expected) {
        return IsNotEqualsConstraint.verify(verifier, v, diff, diffinv, expected);
    }
}
