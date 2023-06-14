package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.curve25519.CompressedRistretto;
import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.*;
import io.airlift.compress.Compressor;
import io.airlift.compress.zstd.ZstdCompressor;
import lombok.Getter;
import org.bitcoinj.base.Base58;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Getter
public class MiMCHashPreImage implements Gadget<MiMCHashPreImageParams> {

    static final Logger logger = LoggerFactory.getLogger(MiMCHashPreImage.class);

    private final GadgetType type = GadgetType.mimc_hash_preimage;

    private final boolean batchProof = false;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = false;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, MiMCHashPreImageParams.class);
    }

    @Override
    public Proof generate(Object value, MiMCHashPreImageParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        List<Long> v = (List<Long>)value;
        Long left = v.get(0);
        Long right = v.get(1);

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment leftComm = prover.commit(Utils.scalar(left), rnd != null ? rnd : Utils.randomScalar());
        Allocated aleft = new Allocated(leftComm.getVariable(), left);
        commitments.add(leftComm.getCommitment());

        Commitment rightComm = prover.commit(Utils.scalar(right), rnd != null ? rnd : Utils.randomScalar());
        Allocated aright = new Allocated(rightComm.getVariable(), right);
        commitments.add(rightComm.getCommitment());

        Scalar image = MiMC.mimc(Utils.scalar(left), Utils.scalar(right), params.getSeed(), params.getRounds());

        if (checkHash(prover, aleft, aright, image, params.getSeed(), params.getRounds())) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(MiMCHashPreImageParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable left = verifier.commit(proof.getCommitment(0));
        Allocated aleft = new Allocated(left, null);

        Variable right = verifier.commit(proof.getCommitment(1));
        Allocated aright = new Allocated(right, null);

        if (checkHash(verifier, aleft, aright, params.getHash(), params.getSeed(), params.getRounds())) {
            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
    }

    public boolean checkHash(ConstraintSystem verifier, Allocated left, Allocated right, Scalar image, long seed, int rounds) {
        LinearCombination hash = MiMCHash.mimc(verifier, LinearCombination.from(left.getVariable()), LinearCombination.from(right.getVariable()), seed, rounds);
        verifier.constrainLCWithScalar(hash, image);
        return true;
    }

    public static String computeMiMCHash(List<Object> row, long seed, int rounds, boolean useZstdCompress) {
        AtomicInteger depth = new AtomicInteger(0);
        AtomicInteger length = new AtomicInteger(0);

        String encoded = MiMCHashPreImage.serializeForHash(row);
        byte[] data;
        if (useZstdCompress) {
            byte[] input = encoded.getBytes(StandardCharsets.UTF_8);
            Compressor compressor = new ZstdCompressor();
            int maxCompressLength = compressor.maxCompressedLength(input.length);
            byte[] compressed = new byte[maxCompressLength];

            int len = compressor.compress(input, 0, input.length, compressed, 0, compressed.length);
            data = Arrays.copyOfRange(compressed, 0, len);
        } else {
            data = encoded.getBytes(StandardCharsets.UTF_8);
        }
        Scalar hash = MiMC.mimcHash(data, seed, rounds, depth, length, useZstdCompress);
        return Base58.encode(hash.toByteArray());
    }

    public static String serializeForHash(List<Object> row) {
        List<Object> toSerialize = new ArrayList<>();
        for (Object i : row) {
            toSerialize.add(
                    i instanceof BigDecimal ? ((BigDecimal) i).doubleValue() : (i instanceof BigInteger ? ((BigInteger) i).longValue() : i)
            );
        }

        return Utils.getGson().toJson(toSerialize);
    }
}
