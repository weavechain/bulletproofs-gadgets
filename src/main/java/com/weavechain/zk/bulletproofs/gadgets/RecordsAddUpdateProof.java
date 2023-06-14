package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.curve25519.CompressedRistretto;
import com.weavechain.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.*;
import io.airlift.compress.Compressor;
import io.airlift.compress.zstd.ZstdCompressor;
import lombok.Getter;
import org.bitcoinj.base.Base58;
import org.bitcoinj.base.Sha256Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Getter
public class RecordsAddUpdateProof implements Gadget<RecordsAddPreImageHashParams> {

    static final Logger logger = LoggerFactory.getLogger(RecordsAddUpdateProof.class);

    private final GadgetType type = GadgetType.records_add_update_proof;

    private final boolean batchProof = true;

    private final boolean numericInput = false;

    private final boolean isMultiColumn = true;

    public static final boolean useZstdCompress = false; //TODO: config

    public static final int HASH_LEN = 32;

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, RecordsAddPreImageHashParams.class);
    }

    public static byte[] hash(byte[] data) {
        return Sha256Hash.hashTwice(data);
    }

    @Override
    public Proof generate(Object value, RecordsAddPreImageHashParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        List<Object> values = (List<Object>)value;

        byte[] fromHash = Base58.decode(params.getFromHash());
        Scalar left = Scalar.fromBits(fromHash);

        String rowHash = MiMCHashPreImage.computeMiMCHash(values, params.getSeed(), params.getRounds(), useZstdCompress);
        Scalar right = Scalar.fromBits(Base58.decode(rowHash));

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        Commitment leftComm = prover.commit(left, rnd != null ? rnd : Utils.randomScalar());
        Allocated aleft = new Allocated(leftComm.getVariable(), Utils.scalarToLong(left));
        commitments.add(leftComm.getCommitment());

        Commitment rightComm = prover.commit(right, rnd != null ? rnd : Utils.randomScalar());
        Allocated aright = new Allocated(rightComm.getVariable(), Utils.scalarToLong(right));
        commitments.add(rightComm.getCommitment());

        Scalar image = MiMC.mimc(left, right, params.getSeed(), params.getRounds());

        if (checkHash(prover, aleft, aright, image, params.getSeed(), params.getRounds())) {
            String encoded = MiMCHashPreImage.serializeForHash(values);
            byte[] data = encoded.getBytes(StandardCharsets.UTF_8);

            byte[] toHash;
            if (useZstdCompress) {
                Compressor compressor = new ZstdCompressor();
                int maxCompressLength = compressor.maxCompressedLength(data.length);
                byte[] compressed = new byte[maxCompressLength];

                int len = compressor.compress(data, 0, data.length, compressed, 0, compressed.length);
                toHash = Arrays.copyOfRange(compressed, 0, len);
            } else {
                toHash = data;
            }

            AtomicInteger depth = new AtomicInteger(0);
            List<LinearCombination> hashes = new ArrayList<>();
            if (MiMCStringHashPreImage.hashBytes(prover, Arrays.copyOfRange(toHash, 0, toHash.length), params.getSeed(), params.getRounds(), rnd, depth, hashes, commitments)) {
                prover.constrainLCWithScalar(LinearCombination.from(aleft.getVariable()), left);

                return new Proof(prover.prove(generators), commitments);
            } else {
                logger.error("Failed statement check");
                return null;
            }
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(RecordsAddPreImageHashParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        Variable left = verifier.commit(proof.getCommitment(0));
        Allocated aleft = new Allocated(left, null);

        Variable right = verifier.commit(proof.getCommitment(1));
        Allocated aright = new Allocated(right, null);

        byte[] resultedHash = Base58.decode(params.getExpectedHash());
        byte[] fromHash = Base58.decode(params.getFromHash());

        if (checkHash(verifier, aleft, aright, Scalar.fromBits(resultedHash), params.getSeed(), params.getRounds())) {
            byte[] data = MiMCHashPreImage.serializeForHash(params.getNewRow()).getBytes(StandardCharsets.UTF_8);
            byte[] toHash;
            if (useZstdCompress) {
                Compressor compressor = new ZstdCompressor();
                int maxCompressLength = compressor.maxCompressedLength(data.length);
                byte[] compressed = new byte[maxCompressLength];

                int len = compressor.compress(data, 0, data.length, compressed, 0, compressed.length);
                toHash = Arrays.copyOfRange(compressed, 0, len);
            } else {
                toHash = data;
            }
            int length = toHash.length;

            List<LinearCombination> hashes = buildHashes(verifier, proof, params.getSeed(), params.getRounds(), length, 2);

            long seed = params.getSeed();
            int rounds = params.getRounds();

            AtomicInteger depth = new AtomicInteger(0);
            AtomicInteger rlength = new AtomicInteger(0);
            Scalar rowHash = MiMC.mimcHash(toHash, seed, rounds, depth, rlength, useZstdCompress);
            verifier.constrainLCWithScalar(hashes.get(hashes.size() - 1), rowHash);

            //TODO: a variant which computes the source hash from all existing data
            verifier.constrainLCWithScalar(LinearCombination.from(aleft.getVariable()), Scalar.fromBits(fromHash));

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

    protected static List<LinearCombination> buildHashes(Verifier verifier, Proof proof, long seed, int rounds, int length, int startIdx) {
        List<LinearCombination> hashes = new ArrayList<>();

        int pairs = length / 64 + (length % 64 != 0 ? 1 : 0);
        for (int i = 0; i < pairs; i++) {
            Variable left = verifier.commit(proof.getCommitment(startIdx + i * 2));
            Allocated aleft = new Allocated(left, null);

            Variable right = verifier.commit(proof.getCommitment(startIdx + i * 2 + 1));
            Allocated aright = new Allocated(right, null);

            LinearCombination hash = MiMCHash.mimc(verifier, LinearCombination.from(aleft.getVariable()), LinearCombination.from(aright.getVariable()), seed, rounds);
            hashes.add(hash);
        }

        while (hashes.size() > 1) {
            hashes = buildHashes(verifier, seed, rounds, hashes);
        }

        return hashes;
    }

    private static List<LinearCombination> buildHashes(ConstraintSystem cs, long seed, int rounds, List<LinearCombination> inputs) {
        List<LinearCombination> hashes = new ArrayList<>();
        for (int i = 0; i < inputs.size(); i += 2) {
            LinearCombination hash = MiMCHash.mimc(cs, inputs.get(i), i + 1 < inputs.size() ? inputs.get(i + 1) : LinearCombination.from(Scalar.ZERO), seed, rounds);
            hashes.add(hash);
        }

        return hashes;
    }
}
