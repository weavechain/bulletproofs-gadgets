package com.weavechain.zk.bulletproofs.gadgets;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Scalar;
import com.weavechain.zk.bulletproofs.*;
import io.airlift.compress.Compressor;
import io.airlift.compress.zstd.ZstdCompressor;
import lombok.Getter;
import org.bitcoinj.base.Base58;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

@Getter
public class MiMCStringHashPreImage implements Gadget<MiMCStringHashPreImageParams> {

    static final Logger logger = LoggerFactory.getLogger(MiMCStringHashPreImage.class);

    private final GadgetType type = GadgetType.mimc_string_hash_preimage;

    private final boolean batchProof = false;

    private final boolean numericInput = false;

    private final boolean isMultiColumn = false;

    public static final boolean useZstdCompress = true; //TODO: config

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        Map<String, Object> items = GsonUtils.getGson().fromJson(params, Map.class);

        int rounds = MiMC.DEFAULT_MIMC_ROUNDS;
        long seed = 0;

        if (items.get("rounds") != null) {
            rounds = ConvertUtils.convertToInteger(items.get("rounds"));
        }
        if (items.get("seed") != null) {
            seed = ConvertUtils.convertToLong(items.get("seed"));
        }
        if (items.get("data") != null && value == null) {
            value = items.get("data");
        }

        if (value != null) {
            String data = ConvertUtils.convertToString(value);
            return MiMCStringHashPreImageParams.from(data, seed, rounds);
        } else if (items.size() > 0) {
            try {
                return GsonUtils.getGsonWithTransient().fromJson(params, MiMCStringHashPreImageParams.class);
            } catch (Exception e) {
                String encodedHash = ConvertUtils.convertToString(items.get("hash"));
                Scalar hash = Scalar.fromBits(Base58.decode(encodedHash));
                int length = ConvertUtils.convertToInteger(items.get("length"));

                return new MiMCStringHashPreImageParams(rounds, seed, hash, length);
            }
        } else {
            return MiMCStringHashPreImageParams.from("", seed, rounds);
        }
    }

    @Override
    public Proof generate(Object value, MiMCStringHashPreImageParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        String v = ConvertUtils.convertToString(value);
        byte[] data = v.getBytes(StandardCharsets.UTF_8);

        byte[] compressed;
        int len;
        if (useZstdCompress) {
            Compressor compressor = new ZstdCompressor();
            int maxCompressLength = compressor.maxCompressedLength(data.length);
            compressed = new byte[maxCompressLength];
            len = compressor.compress(data, 0, data.length, compressed, 0, compressed.length);
        } else {
            compressed = data;
            len = data.length;
        }

        List<CompressedRistretto> commitments = new ArrayList<>();
        List<LinearCombination> hashes = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        AtomicInteger depth = new AtomicInteger(0);

        if (hashBytes(prover, Arrays.copyOfRange(compressed, 0, len), params.getSeed(), params.getRounds(), rnd, depth, hashes, commitments)) {
            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(MiMCStringHashPreImageParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        List<LinearCombination> hashes = buildHashes(verifier, proof, params.getSeed(), params.getRounds(), params.getLength(), 0);
        verifier.constrainLCWithScalar(hashes.get(hashes.size() - 1), params.getHash());

        return verifier.verify(proof, pedersenCommitment, generators);
    }

    protected static List<LinearCombination> buildHashes(Verifier verifier, Proof proof, long seed, int rounds, int length, int startIdx) {
        List<LinearCombination> hashes = new ArrayList<>();

        for (int i = 0; i < length / 2; i++) {
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

    protected static boolean hashBytes(Prover prover, byte[] data, long seed, int rounds, Scalar rnd, AtomicInteger depth, List<LinearCombination> hashes, List<CompressedRistretto> commitments) {
        int len = data.length;
        int d = depth.incrementAndGet();
        int pairs = len / 64 + (len % 64 != 0 ? 1 : 0);

        byte[] output = new byte[32 * pairs];
        for (int i = 0; i < pairs; i++) {
            int idx = i * 64;
            byte[] l = new byte[32];
            System.arraycopy(data, idx, l, 0, Math.min(32, len - idx));
            byte[] r = new byte[32];
            if (idx + 32 < len) {
                System.arraycopy(data, idx + 32, r, 0, Math.min(32, len - idx - 32));
            }

            //TODO: might need to check for invalid scalar representations if (l[31] >> 7 & 1) != 0 and add a workaround
            Scalar left = Scalar.fromBits(l);
            Scalar right = Scalar.fromBits(r);

            //TODO: evaluate adding commitments on every step

            if (d == 1) {
                Commitment leftComm = prover.commit(left, rnd != null ? rnd : Utils.randomScalar());
                Allocated aleft = new Allocated(leftComm.getVariable(), Utils.scalarToLong(left));
                commitments.add(leftComm.getCommitment());

                Commitment rightComm = prover.commit(right, rnd != null ? rnd : Utils.randomScalar());
                Allocated aright = new Allocated(rightComm.getVariable(), Utils.scalarToLong(right));
                commitments.add(rightComm.getCommitment());

                LinearCombination hash = MiMCHash.mimc(prover, LinearCombination.from(aleft.getVariable()), LinearCombination.from(aright.getVariable()), seed, rounds);
                hashes.add(hash);
            }

            Scalar image = MiMC.mimc(left, right, seed, rounds);
            System.arraycopy(image.toByteArray(), 0, output, i * 32, 32);
        }

        if (d == 1) {
            while (hashes.size() > 1) {
                hashes = buildHashes(prover, seed, rounds, hashes);
            }
        }

        if (output.length == 32) {
            prover.constrainLCWithScalar(hashes.get(hashes.size() - 1), Scalar.fromBits(output));

            return true;
        } else {
            return hashBytes(prover, output, seed, rounds, null, depth, hashes, commitments);
        }
    }
}
