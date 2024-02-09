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
public class NumberIsLessOrEqual implements Gadget<NumberIsLessOrEqualParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberIsLessOrEqual.class);

    private final GadgetType type = Gadgets.number_is_less_or_equal;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberIsLessOrEqualParams.class);
    }

    @Override
    public Proof generate(Object value, NumberIsLessOrEqualParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        BigInteger v = ConvertUtils.convertToBigInteger(value);
        Integer bitsize = params.getBitsize();

        BigInteger b = params.getMax().subtract(v);

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        Commitment bComm = prover.commit(Utils.scalar(b), Utils.randomScalar());
        Allocated ab = new Allocated(bComm.getVariable(), b);
        commitments.add(bComm.getCommitment());

        if (checkLess(prover, av, ab, params.getMax(), bitsize)) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberIsLessOrEqualParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        Variable b = verifier.commit(proof.getCommitment(1));
        Allocated ab = new Allocated(b, null);

        if (checkLess(verifier, av, ab, params.getMax(), params.getBitsize())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkLess(ConstraintSystem cs, Allocated v, Allocated b, BigInteger max, Integer bitsize) {
        cs.constrain(LinearCombination.from(Utils.scalar(max)).sub(LinearCombination.from(v.getVariable())).sub(LinearCombination.from(b.getVariable())));

        return IsPositiveConstraint.verify(cs, b, bitsize);
    }
}
