package com.weavechain.zk.bulletproofs.gadgets;


import cafe.cryptography.curve25519.Scalar;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.weavechain.zk.bulletproofs.Utils;
import io.airlift.compress.Compressor;
import io.airlift.compress.zstd.ZstdCompressor;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

public class MiMC {

    private static final int MAX_CACHE_CAPACITY = 10;

    public static final int DEFAULT_MIMC_ROUNDS = 322;

    private static final Cache<LongPair, List<Scalar>> CONSTANTS = Caffeine.newBuilder().maximumSize(MAX_CACHE_CAPACITY).build();

    public static List<Scalar> getConstants(long seed, int rounds) {
        synchronized (CONSTANTS) {
            LongPair pair = new LongPair(seed, (long)rounds);
            List<Scalar> result = CONSTANTS.getIfPresent(pair);

            if (result == null) {
                result = new ArrayList<>();

                Random rnd = new Random(seed); // new DrngImpl(AesCtrDrbgFactory.fromDerivedSeed((byte)seed))
                for (int i = 0; i < rounds; i++) {
                    result.add(Utils.scalar(rnd.nextLong()));
                }

                CONSTANTS.put(pair, result);
            }
            return result;
        }
    }

    public static Scalar mimc(Scalar left, Scalar right, long seed, int rounds) {
        Scalar xl = left;
        Scalar xr = right;

        List<Scalar> constants = getConstants(seed, rounds);

        for (int i = 0; i < rounds; i++) {
            Scalar tmp1 = xl.add(constants.get(i));
            Scalar tmp2 = tmp1.multiply(tmp1).multiplyAndAdd(tmp1, xr);
            xr = xl;
            xl = tmp2;
        }

        return xl;
    }

    public static Scalar mimcHash(byte[] data, long seed, int rounds, AtomicInteger depth, AtomicInteger length, boolean useZstdCompress) {
        return useZstdCompress ? compressedHash(data, seed, rounds, depth, length) : hash(data, seed, rounds, depth, length);
    }

    public static Scalar compressedHash(byte[] data, long seed, int rounds, AtomicInteger depth, AtomicInteger length) {
        Compressor compressor = new ZstdCompressor();
        int maxCompressLength = compressor.maxCompressedLength(data.length);
        byte[] compressed = new byte[maxCompressLength];
        int len = compressor.compress(data, 0, data.length, compressed, 0, compressed.length);

        byte[] result = hashBytes(Arrays.copyOfRange(compressed, 0, len), seed, rounds, depth, length);
        return Scalar.fromBits(result);
    }

    public static Scalar hash(byte[] data, long seed, int rounds, AtomicInteger depth, AtomicInteger length) {
        byte[] result = hashBytes(data, seed, rounds, depth, length);
        return Scalar.fromBits(result);
    }

    private static byte[] hashBytes(byte[] input, long seed, int rounds, AtomicInteger depth, AtomicInteger length) {
        int len = input.length;
        depth.incrementAndGet();
        int pairs = len / 64 + (len % 64 != 0 ? 1 : 0);
        if (length != null) {
            length.set(pairs * 2);
        }

        byte[] output = new byte[32 * pairs];
        for (int i = 0; i < pairs; i++) {
            int idx = i * 64;
            byte[] left = new byte[32];
            System.arraycopy(input, idx, left, 0, Math.min(32, len - idx));
            byte[] right = new byte[32];
            if (idx + 32 < len) {
                System.arraycopy(input, idx + 32, right, 0, Math.min(32, len - idx - 32));
            }

            Scalar hash = MiMC.mimc(Scalar.fromBits(left), Scalar.fromBits(right), seed, rounds);
            System.arraycopy(hash.toByteArray(), 0, output, i * 32, 32);
        }

        return output.length == 32 ? output : hashBytes(output, seed, rounds, depth, null);
    }

    @Getter
    @EqualsAndHashCode
    @AllArgsConstructor
    public static class LongPair {

        private final Long v1;

        private final Long v2;
    }
}
