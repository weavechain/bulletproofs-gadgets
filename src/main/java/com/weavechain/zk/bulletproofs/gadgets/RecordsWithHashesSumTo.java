package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.curve25519.CompressedRistretto;
import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.*;
import lombok.Getter;
import org.bitcoinj.base.Base58;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Getter
public class RecordsWithHashesSumTo implements Gadget<RecordsWithHashesSumToParams> {

    static final Logger logger = LoggerFactory.getLogger(RecordsWithHashesSumTo.class);

    private final GadgetType type = Gadgets.records_with_hashes_sum_to;

    private final boolean batchProof = true;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = true;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, RecordsWithHashesSumToParams.class);
    }

    @Override
    public Proof generate(Object value, RecordsWithHashesSumToParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        List<List<Object>> values = (List<List<Object>>)value;

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        byte[] salt = params.getSalt().getBytes(StandardCharsets.UTF_8);
        String digest = null; //use configured default

        Long sum = 0L;
        List<LinearCombination> sums = new ArrayList<>();
        for (List<Object> it : values) {
            String encoded = MiMCHashPreImage.serializeForHash(it);

            byte hash[] = Hash.signString(salt, encoded, digest);

            byte[] hash2 = new byte[32];
            hash2[0] = hash[31];
            hash[31] = 0;
            Scalar hashScalar = Scalar.fromBits(hash);
            Scalar hashScalar2 = Scalar.fromBits(hash2);

            Commitment vComm = prover.commit(hashScalar, rnd != null ? rnd : Utils.randomScalar());
            Allocated av = new Allocated(vComm.getVariable(), Utils.scalarToLong(hashScalar));
            commitments.add(vComm.getCommitment());

            Commitment diffComm = prover.commit(hashScalar2, Utils.randomScalar());
            Allocated adiff = new Allocated(diffComm.getVariable(), Utils.scalarToLong(hashScalar2));
            commitments.add(diffComm.getCommitment());

            prover.constrainLCWithScalar(LinearCombination.from(av.getVariable()), hashScalar);
            prover.constrainLCWithScalar(LinearCombination.from(adiff.getVariable()), hashScalar2);

            int indexValue = params.getSumColumnIndex();
            Long v = ConvertUtils.convertToLong(it.get(indexValue));

            Commitment sumComm = prover.commit(Utils.scalar(sum), rnd != null ? rnd : Utils.randomScalar());
            Allocated asum = new Allocated(sumComm.getVariable(), sum);
            commitments.add(sumComm.getCommitment());

            Commitment valComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
            Allocated aval = new Allocated(valComm.getVariable(), v);
            commitments.add(valComm.getCommitment());

            LinearCombination next = LinearCombination.from(asum.getVariable()).clone().add(LinearCombination.from(aval.getVariable()));
            sums.add(next);

            sum += v;
        }
        prover.constrainLCWithScalar(sums.get(sums.size() - 1), Utils.scalar(sum));

        Commitment vComm = prover.commit(Utils.scalar(sum), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), sum);
        commitments.add(vComm.getCommitment());

        Scalar diff = Utils.scalar(params.getExpected()).subtract(Utils.scalar(sum));
        Commitment diffComm = prover.commit(diff, Utils.randomScalar());
        Allocated adiff = new Allocated(diffComm.getVariable(), Utils.scalarToLong(diff));
        commitments.add(diffComm.getCommitment());

        if (checkSumEqual(prover, av, adiff, values.size(), params.getExpected(), params.getBitsize())) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(RecordsWithHashesSumToParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        List<LinearCombination> sums = buildSums(verifier, proof, params.getCount(), params.getHashes(), params.getBitsize());

        verifier.constrainLCWithScalar(sums.get(sums.size() - 1), Utils.scalar(params.getExpected()));

        Variable v = verifier.commit(proof.getCommitment(sums.size() * 4));
        Allocated av = new Allocated(v, null);

        Variable vdiff = verifier.commit(proof.getCommitment(sums.size() * 4 + 1));
        Allocated adiff = new Allocated(vdiff, null);

        if (checkSumEqual(verifier, av, adiff, sums.size(), params.getExpected(), params.getBitsize())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    private List<LinearCombination> buildSums(Verifier verifier, Proof proof, int count, List<String> hashes, int bitSize) {
        List<LinearCombination> sums = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            Variable v = verifier.commit(proof.getCommitment(i * 4));
            Allocated av = new Allocated(v, null);

            Variable diff = verifier.commit(proof.getCommitment(i * 4 + 1));
            Allocated adiff = new Allocated(diff, null);

            byte[] hash = Base58.decode(hashes.get(i));
            byte[] hash2 = new byte[32];
            hash2[0] = hash[31];
            hash[31] = 0;

            verifier.constrainLCWithScalar(LinearCombination.from(av.getVariable()), Scalar.fromBits(hash));
            verifier.constrainLCWithScalar(LinearCombination.from(adiff.getVariable()), Scalar.fromBits(hash2));

            Variable sum = verifier.commit(proof.getCommitment(i * 4 + 2));
            Allocated asum = new Allocated(sum, null);

            Variable val = verifier.commit(proof.getCommitment(i * 4 + 3));
            Allocated aval = new Allocated(val, null);

            LinearCombination next = LinearCombination.from(asum.getVariable()).clone().add(LinearCombination.from(aval.getVariable()));
            sums.add(next);
        }

        return sums;
    }

    public boolean checkSumEqual(ConstraintSystem verifier, Allocated v, Allocated diff, int count, Long expected, int bitsize) {
        if (count == 0) {
            return expected == 0;
        } else {
            LinearCombination product = LinearCombination.from(Variable.ONE);

            verifier.constrainLCWithScalar(LinearCombination.from(diff.getVariable()).add(LinearCombination.from(v.getVariable())), Utils.scalar(expected));

            Variable o1 = verifier.multiply(product, LinearCombination.from(diff.getVariable())).getOutput();
            product = LinearCombination.from(o1);

            verifier.constrain(product);

            return IsPositiveConstraint.verify(verifier, v, bitsize);
        }
    }
}

