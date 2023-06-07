package com.weavechain.zk.bulletproofs.gadgets;

import cafe.cryptography.curve25519.Scalar;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.weavechain.zk.bulletproofs.Utils;

import java.lang.reflect.Modifier;

public class GsonUtils {

    private static final ThreadLocal<Gson> gson = ThreadLocal.withInitial(GsonUtils::createGson);

    private static final ThreadLocal<Gson> gsonWithTransient = ThreadLocal.withInitial(GsonUtils::createGsonWithTransient);

    public static Gson getGson() {
        return gson.get();
    }

    public static Gson getGsonWithTransient() {
        return gsonWithTransient.get();
    }

    public static Gson createGson() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(Scalar.class, new Utils.ScalarSerializer());
        return gsonBuilder.create();
    }

    public static Gson createGsonWithTransient() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(Scalar.class, new Utils.ScalarSerializer());
        return gsonBuilder.excludeFieldsWithModifiers(Modifier.STATIC).create();
    }
}