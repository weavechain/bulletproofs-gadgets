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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Getter
public class RecordsWithHashPreImageSumTo implements Gadget<RecordsWithHashPreImageSumToParams> {

    static final Logger logger = LoggerFactory.getLogger(RecordsWithHashPreImageSumTo.class);

    private final GadgetType type = Gadgets.records_with_hash_preimage_sum_to;

    private final boolean batchProof = true;

    private final boolean numericInput = true;

    private final boolean isMultiColumn = true;

    public static final boolean useZstdCompress = false; //TODO: config

    @Override
    public GadgetParams unpackParams(String params, Object value) {
        return GsonUtils.getGsonWithTransient().fromJson(params, RecordsWithHashPreImageSumToParams.class);
    }

    public static byte[] hash(byte[] data) {
        return Sha256Hash.hashTwice(data);
    }

    @Override
    public Proof generate(Object value, RecordsWithHashPreImageSumToParams params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        List<List<Object>> values = (List<List<Object>>)value;

        List<CompressedRistretto> commitments = new ArrayList<>();

        Transcript transcript = new Transcript();
        Prover prover = new Prover(transcript, pedersenCommitment);

        List<byte[]> hashData = new ArrayList<>();
        BigInteger sum = BigInteger.ZERO;
        List<LinearCombination> sums = new ArrayList<>();
        for (List<Object> it : values) {
            String encoded = MiMCHashPreImage.serializeForHash(it);

            byte[] data = encoded.getBytes(StandardCharsets.UTF_8);

            byte[] toHash;
            if (useZstdCompress) {
                //TODO: add committment? or drop compress
                Compressor compressor = new ZstdCompressor();
                int maxCompressLength = compressor.maxCompressedLength(data.length);
                byte[] compressed = new byte[maxCompressLength];

                int len = compressor.compress(data, 0, data.length, compressed, 0, compressed.length);
                toHash = Arrays.copyOfRange(compressed, 0, len);
            } else {
                toHash = data;
            }
            hashData.add(toHash);

            int indexValue = params.getSumColumnIndex();
            BigInteger v = ConvertUtils.convertToBigInteger(it.get(indexValue));

            Commitment sumComm = prover.commit(Utils.scalar(sum), rnd != null ? rnd : Utils.randomScalar());
            Allocated asum = new Allocated(sumComm.getVariable(), sum);
            commitments.add(sumComm.getCommitment());

            //TODO: link this committment with the hash pre-image computation
            Commitment valComm = prover.commit(Utils.scalar(v), rnd != null ? rnd : Utils.randomScalar());
            Allocated aval = new Allocated(valComm.getVariable(), v);
            commitments.add(valComm.getCommitment());

            LinearCombination next = LinearCombination.from(asum.getVariable()).clone().add(LinearCombination.from(aval.getVariable()));
            sums.add(next);

            sum = sum.add(v);
        }
        prover.constrainLCWithScalar(sums.get(sums.size() - 1), Utils.scalar(sum));

        Commitment vComm = prover.commit(Utils.scalar(sum), rnd != null ? rnd : Utils.randomScalar());
        Allocated av = new Allocated(vComm.getVariable(), sum);
        commitments.add(vComm.getCommitment());

        Scalar diff = Utils.scalar(params.getExpected()).subtract(Utils.scalar(sum));
        Commitment diffComm = prover.commit(diff, Utils.randomScalar());
        Allocated adiff = new Allocated(diffComm.getVariable(), Utils.toBigInteger(diff));
        commitments.add(diffComm.getCommitment());

        if (checkSumEqual(prover, av, adiff, values.size(), params.getExpected(), params.getBitsize())) {
            for (byte[] toHash : hashData) {
                AtomicInteger depth = new AtomicInteger(0);
                List<LinearCombination> hashes = new ArrayList<>();
                if (!MiMCStringHashPreImage.hashBytes(prover, toHash, params.getSeed(), params.getRounds(), Utils.randomScalar(), depth, hashes, commitments)) {
                    logger.error("Failed statement check");
                    return null;
                }
            }

            return new Proof(prover.prove(generators), commitments);
        } else {
            logger.error("Failed statement check");
            return null;
        }
    }

    @Override
    public boolean verify(RecordsWithHashPreImageSumToParams params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        Transcript transcript = new Transcript();
        Verifier verifier = new Verifier(transcript);

        int count = params.getCount();
        List<String> hashes = params.getHashes();
        long seed = params.getSeed();
        int rounds = params.getRounds();

        List<LinearCombination> sums = new ArrayList<>();

        List<byte[]> hashData = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            byte[] hash = Base58.decode(hashes.get(i));
            hashData.add(hash);

            Variable sum = verifier.commit(proof.getCommitment(i * 2));
            Allocated asum = new Allocated(sum, null);

            Variable val = verifier.commit(proof.getCommitment(i * 2 + 1));
            Allocated aval = new Allocated(val, null);

            LinearCombination next = LinearCombination.from(asum.getVariable()).clone().add(LinearCombination.from(aval.getVariable()));
            sums.add(next);
        }

        verifier.constrainLCWithScalar(sums.get(sums.size() - 1), Utils.scalar(params.getExpected()));

        Variable v = verifier.commit(proof.getCommitment(sums.size() * 2));
        Allocated av = new Allocated(v, null);

        Variable vdiff = verifier.commit(proof.getCommitment(sums.size() * 2 + 1));
        Allocated adiff = new Allocated(vdiff, null);

        if (checkSumEqual(verifier, av, adiff, sums.size(), params.getExpected(), params.getBitsize())) {
            int startIdx = count * 2 + 2;
            for (byte[] hash : hashData) {
                Scalar hashScalar = Scalar.fromBits(hash);

                int len = 64; //TODO: !!! we need the size of serialziations (or a max size and padding)
                int pairs = len / 64 + (len % 64 != 0 ? 1 : 0);
                List<LinearCombination> recHashes = MiMCStringHashPreImage.buildHashes(verifier, proof, seed, rounds, pairs * 2, startIdx);
                startIdx += pairs * 2;

                verifier.constrainLCWithScalar(recHashes.get(recHashes.size() - 1), hashScalar);
            }

            return verifier.verify(proof, pedersenCommitment, generators);
        } else {
            return false;
        }
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

