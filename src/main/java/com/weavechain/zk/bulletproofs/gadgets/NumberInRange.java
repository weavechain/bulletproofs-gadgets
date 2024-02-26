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
public class NumberInRange implements Gadget<NumberInRangeParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberInRange.class);

    private final GadgetType type = Gadgets.number_in_range;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberInRangeParams.class);
    }

    @Override
    public Proof generate(Object value, NumberInRangeParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        BigInteger v = ConvertUtils.convertToBigInteger(value);
        Integer bitsize = params.getBitsize();

        BigInteger a = v.subtract(params.getMin());
        BigInteger b = params.getMax().subtract(v);

        List<ECPoint> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        Commitment aComm = prover.commit(Utils.scalar(a), Utils.randomScalar());
        Allocated aa = new Allocated(aComm.getVariable(), a);
        commitments.add(aComm.getCommitment());

        Commitment bComm = prover.commit(Utils.scalar(b), Utils.randomScalar());
        Allocated ab = new Allocated(bComm.getVariable(), b);
        commitments.add(bComm.getCommitment());

        if (checkBound(prover, av, aa, ab, params.getMin(), params.getMax(), bitsize)) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberInRangeParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        Variable a = verifier.commit(proof.getCommitment(1));
        Allocated aa = new Allocated(a, null);

        Variable b = verifier.commit(proof.getCommitment(2));
        Allocated ab = new Allocated(b, null);

        if (checkBound(verifier, av, aa, ab, params.getMin(), params.getMax(), params.getBitsize())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkBound(ConstraintSystem cs, Allocated v, Allocated a, Allocated b, BigInteger min, BigInteger max, Integer bitsize) {
        cs.constrain(LinearCombination.from(v.getVariable()).sub(LinearCombination.from(Utils.scalar(min))).sub(LinearCombination.from(a.getVariable())));
        cs.constrain(LinearCombination.from(Utils.scalar(max)).sub(LinearCombination.from(v.getVariable())).sub(LinearCombination.from(b.getVariable())));

        cs.constrainLCWithScalar(LinearCombination.from(a.getVariable()).add(LinearCombination.from(b.getVariable())), Utils.scalar(max.subtract(min)));

        return IsPositiveConstraint.verify(cs, a, bitsize) && IsPositiveConstraint.verify(cs, b, bitsize);
    }
}
