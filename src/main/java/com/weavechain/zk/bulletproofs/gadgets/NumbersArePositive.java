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
public class NumbersArePositive implements Gadget<NumbersArePositiveParams> {

    static final Logger logger = LoggerFactory.getLogger(NumbersArePositive.class);

    private final GadgetType type = Gadgets.numbers_are_positive;

    private final boolean batchProof = true;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumbersArePositiveParams.class);
    }

    @Override
    public Proof generate(Object value, NumbersArePositiveParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        List<Long> values = ConvertUtils.convertToLongList(value);
        Integer bitsize = params.getBitsize();

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        for (Long v : values) {
            Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
            Allocated av = new Allocated(vComm.getVariable(), v);
            commitments.add(vComm.getCommitment());

            if (!checkPositive(prover, av, bitsize)) {
                logger.error("Failed statement check");
                return null;
            }
        }

        return new Proof(prover.prove(generators), commitments);
    }

    @Override
    public boolean verify(NumbersArePositiveParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Integer bitsize = params.getBitsize();

        for (int i = 0; i < params.getCount(); i++) {
            Variable v = verifier.commit(proof.getCommitment(i));
            Allocated av = new Allocated(v, null);

            if (!checkPositive(verifier, av, bitsize)) {
                return false;
            }
        }

        return verifier.verify(proof, pedersenCommitment, generators);
    }

    public boolean checkPositive(ConstraintSystem verifier, Allocated v, Integer bitsize) {
        return IsPositiveConstraint.verify(verifier, v, bitsize);
    }
}
