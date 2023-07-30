package com.weavechain.zk.bulletproofs.gadgets;

import com.weavechain.zk.bulletproofs.BulletProofs;
import com.weavechain.zk.bulletproofs.GadgetType;

public class Gadgets {

    //Some gadgets based on https://github.com/lovesh/bulletproofs-r1cs-gadgets
    //  see LICENSE-orig.txt

    public static GadgetType number_in_range = new GadgetImpl("number_in_range");

    public static GadgetType numbers_in_range = new GadgetImpl("numbers_in_range");

    public static GadgetType number_is_positive = new GadgetImpl("number_is_positive");

    public static GadgetType numbers_are_positive = new GadgetImpl("numbers_are_positive");

    public static GadgetType numbers_sum_to = new GadgetImpl("numbers_sum_to");

    public static GadgetType records_with_hashes_sum_to = new GadgetImpl("records_with_hashes_sum_to");

    public static GadgetType records_with_hash_preimage_sum_to = new GadgetImpl("records_with_hash_preimage_sum_to");

    public static GadgetType records_add_update_proof = new GadgetImpl("records_add_update_proof");

    public static GadgetType number_is_greater_or_equal = new GadgetImpl("number_is_greater_or_equal");

    public static GadgetType number_is_less_or_equal = new GadgetImpl("number_is_less_or_equal");

    public static GadgetType number_is_not_equal = new GadgetImpl("number_is_not_equal");

    public static GadgetType number_is_non_zero = new GadgetImpl("number_is_non_zero");

    public static GadgetType numbers_are_non_zero = new GadgetImpl("numbers_are_non_zero");

    public static GadgetType number_is_zero = new GadgetImpl("number_is_zero");

    public static GadgetType number_is_equal = new GadgetImpl("number_is_equal");

    public static GadgetType number_in_list = new GadgetImpl("number_in_list");

    public static GadgetType number_not_in_list = new GadgetImpl("number_not_in_list");

    public static GadgetType mimc_hash_preimage = new GadgetImpl("mimc_hash_preimage");

    public static GadgetType mimc_string_hash_preimage = new GadgetImpl("mimc_string_hash_preimage");

    public static GadgetType sha256_hash_preimage = new GadgetImpl("sha256_hash_preimage");

    public static void registerGadgets(BulletProofs bulletProofs) {
        bulletProofs.registerGadget(new NumberInRange());
        bulletProofs.registerGadget(new NumbersInRange());
        bulletProofs.registerGadget(new NumberIsPositive());
        bulletProofs.registerGadget(new NumbersArePositive());
        bulletProofs.registerGadget(new NumbersSumTo());
        bulletProofs.registerGadget(new RecordsWithHashesSumTo());
        bulletProofs.registerGadget(new RecordsWithHashPreImageSumTo());
        bulletProofs.registerGadget(new RecordsAddUpdateProof());
        bulletProofs.registerGadget(new NumberIsNonZero());
        bulletProofs.registerGadget(new NumbersAreNonZero());
        bulletProofs.registerGadget(new NumberIsZero());
        bulletProofs.registerGadget(new NumberIsNotEqual());
        bulletProofs.registerGadget(new NumberIsEqual());
        bulletProofs.registerGadget(new NumberInList());
        bulletProofs.registerGadget(new NumberNotInList());
        bulletProofs.registerGadget(new NumberIsGreaterOrEqual());
        bulletProofs.registerGadget(new NumberIsLessOrEqual());
        bulletProofs.registerGadget(new MiMCHashPreImage());
        bulletProofs.registerGadget(new MiMCStringHashPreImage());
    }
}