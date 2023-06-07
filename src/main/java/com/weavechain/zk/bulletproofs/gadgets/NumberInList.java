package com.weavechain.zk.bulletproofs.gadgets;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.*;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

@Getter
public class NumberInList implements Gadget<NumberInListParams> {

    static final Logger logger = LoggerFactory.getLogger(NumberInList.class);

    private final GadgetType type = GadgetType.number_in_list;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, NumberInListParams.class);
    }

    @Override
    public Proof generate(Object value, NumberInListParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Long v = ConvertUtils.convertToLong(value);
        Integer bitsize = params.getBitsize();

        List<Allocated> diffs = new ArrayList<>();
        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment vComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), v);
        commitments.add(vComm.getCommitment());

        for (Long it : params.getList()) {
            Scalar diff = Utils.scalar(it).subtract(Utils.scalar(v));
            Commitment diffComm = prover.commit(diff, Utils.randomScalar());
            Allocated adiff = new Allocated(diffComm.getVariable(), v);

            diffs.add(adiff);
            commitments.add(diffComm.getCommitment());
        }

        if (checkInList(prover, av, diffs, params.getList(), bitsize)) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(NumberInListParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Integer bitsize = params.getBitsize();

        Variable v = verifier.commit(proof.getCommitment(0));
        Allocated av = new Allocated(v, null);

        List<Allocated> diffs = new ArrayList<>();
        for (int i = 0; i < params.getList().size(); i++) {
            CompressedRistretto committment = proof.getCommitments().get(i + 1);
            Variable diffComm = verifier.commit(committment);
            Allocated adiff = new Allocated(diffComm, null);

            diffs.add(adiff);
        }

        if (checkInList(verifier, av, diffs, params.getList(), bitsize)) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkInList(ConstraintSystem verifier, Allocated v, List<Allocated> diffs, List<Long> list, Integer bitsize) {
        LinearCombination product = LinearCombination.from(Variable.ONE);

        for (int i = 0; i < diffs.size(); i++) {
            verifier.constrainLCWithScalar(LinearCombination.from(diffs.get(i).getVariable()).add(LinearCombination.from(v.getVariable())), Utils.scalar(list.get(i)));

            Variable o1 = verifier.multiply(product, LinearCombination.from(diffs.get(i).getVariable())).getOutput();
            product = LinearCombination.from(o1);
        }

        verifier.constrain(product);

        return IsPositiveConstraint.verify(verifier, v, bitsize);
    }
}
