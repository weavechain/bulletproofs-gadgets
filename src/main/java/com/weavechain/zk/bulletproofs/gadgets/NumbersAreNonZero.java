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
public class NumbersAreNonZero implements Gadget<NumbersAreNonZeroParams> {

    static final Logger logger = LoggerFactory.getLogger(NumbersAreNonZero.class);

    private final GadgetType type = Gadgets.numbers_are_non_zero;

    private final boolean batchProof = true;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumbersAreNonZeroParams.class);
    }

    @Override
    public Proof generate(Object value, NumbersAreNonZeroParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        List<BigInteger> values = ConvertUtils.convertToBigIntegerList(value);

        List<ECPoint> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        for (BigInteger v : values) {
            Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
            Allocated av = new Allocated(vComm.getVariable(), v);
            commitments.add(vComm.getCommitment());

            Scalar ainv = Utils.scalar(v).invert();
            Commitment ainvComm = prover.commit(ainv, Utils.randomScalar());
            Allocated avinv = new Allocated(ainvComm.getVariable(), Utils.toBigInteger(ainv));
            commitments.add(ainvComm.getCommitment());

            if (!checkNonZero(prover, av, avinv)) {
                logger.error("Failed statement check");
                return null;
            }
        }

        return new Proof(prover.prove(generators), commitments);
    }

    @Override
    public boolean verify(NumbersAreNonZeroParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        for (int i = 0; i < params.getCount(); i++) {
            Variable v = verifier.commit(proof.getCommitment(i * 2));
            Allocated av = new Allocated(v, null);

            Variable vinv = verifier.commit(proof.getCommitment(i * 2 + 1));
            Allocated ainv = new Allocated(vinv, null);

            if (!checkNonZero(verifier, av, ainv)) {
                return false;
            }
        }

        return verifier.verify(proof, pedersenCommitment, generators);
    }

    public boolean checkNonZero(ConstraintSystem verifier, Allocated x, Allocated xinv) {
        return IsNonZeroConstraint.verify(verifier, x, xinv);
    }
}
