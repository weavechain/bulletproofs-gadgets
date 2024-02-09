package com.weavechain.zk.bulletproofs.gadgets;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class ConvertUtils {

    private static final ZoneId zoneUTC = ZoneId.of("UTC");

    public static Integer convertToInteger(Object obj) {
        return convertToInteger(obj, null);
    }

    public static Integer convertToInteger(Object obj, Integer defaultValue) {
        Long result = convertToLong(obj, defaultValue != null ? defaultValue.longValue() : null);
        return result != null ? result.intValue() : defaultValue;
    }

    public static List<Long> convertToLongList(Object obj) {
        List<Long> result = new ArrayList<>();
        if (obj instanceof List) {
            for (Object it : (List)obj) {
                result.add(convertToLong(it, null));
            }
        } else {
            return null;
        }

        return result;
    }

    public static List<BigInteger> convertToBigIntegerList(Object obj) {
        List<BigInteger> result = new ArrayList<>();
        if (obj instanceof List) {
            for (Object it : (List)obj) {
                result.add(convertToBigInteger(it, null));
            }
        } else {
            return null;
        }

        return result;
    }

    public static Long convertToLong(Object obj) {
        return convertToLong(obj, null);
    }

    public static Long convertToLong(Object obj, Long defaultValue) {
        if (obj == null || obj.toString().isEmpty() || "null".equals(obj.toString().toLowerCase(Locale.ROOT))) {
            return defaultValue;
        } else if (obj instanceof Boolean) {
            return (Boolean)obj ? 1L : 0L;
        } else if (obj instanceof Long) {
            return (Long)obj;
        } else if (obj instanceof Integer) {
            return ((Integer)obj).longValue();
        } else if (obj instanceof Double) {
            return ((Double)obj).longValue();
        } else if (obj instanceof String) {
            return convertToDouble(obj).longValue();
        } else if (obj instanceof BigInteger) {
            return ((BigInteger) obj).longValue();
        } else if (obj instanceof BigDecimal) {
            return ((BigDecimal) obj).longValue();
        } else {
            return (long)Double.parseDouble(obj.toString());
        }
    }

    public static Float convertToFloat(Object obj) {
        return convertToFloat(obj, null);
    }

    public static Float convertToFloat(Object obj, Float defaultValue) {
        Double value = convertToDouble(obj, defaultValue != null ? defaultValue.doubleValue() : null);
        return value != null ? value.floatValue() : null;
    }

    public static Double convertToDouble(Object obj) {
        return convertToDouble(obj, null);
    }

    public static Double convertToDouble(Object obj, Double defaultValue) {
        if (obj == null || obj.toString().isEmpty() || "null".equals(obj.toString().toLowerCase(Locale.ROOT))) {
            return defaultValue;
        } else if (obj instanceof Boolean) {
            return (Boolean)obj ? 1.0 : 0.0;
        } else if (obj instanceof Long) {
            return (double)(Long)obj;
        } else if (obj instanceof Integer) {
            return (double)((Integer)obj);
        } else if (obj instanceof Float) {
            return (double)((Float)obj);
        } else if (obj instanceof Double) {
            return ((Double)obj);
        } else if (obj instanceof BigInteger) {
            return ((BigInteger) obj).doubleValue();
        } else if (obj instanceof BigDecimal) {
            return ((BigDecimal) obj).doubleValue();
        } else if (obj instanceof String) {
            String item = ((String)obj).trim();
            if (item.contains(" ")) {
                //try timestamp conversion
                LocalDateTime date = LocalDateTime.parse(item, FormatUtils.FMT_DATE_FORMAT.get());
                return (double)date.atZone(zoneUTC).toInstant().toEpochMilli();
            } else {
                return Double.parseDouble(item);
            }
        } else {
            return Double.parseDouble(obj.toString());
        }
    }

    public static BigInteger convertToBigInteger(Object obj) {
        return convertToBigInteger(obj, null);
    }

    public static BigInteger convertToBigInteger(Object obj, BigInteger defaultValue) {
        if (obj == null || obj.toString().isEmpty() || "null".equals(obj.toString().toLowerCase(Locale.ROOT))) {
            return defaultValue;
        } else if (obj instanceof Boolean) {
            return (Boolean)obj ? BigInteger.ONE : BigInteger.ZERO;
        } else if (obj instanceof Long) {
            return BigInteger.valueOf((long)obj);
        } else if (obj instanceof Integer) {
            return BigInteger.valueOf((long)((Integer)obj));
        } else if (obj instanceof Double) {
            return BigInteger.valueOf(((Double)obj).longValue());
        } else if (obj instanceof BigDecimal) {
            return ((BigDecimal)obj).toBigInteger();
        } else if (obj instanceof String) {
            return new BigInteger((String)obj);
        } else {
            return BigInteger.valueOf((long)(Double.parseDouble(obj.toString())));
        }
    }

    public static BigDecimal convertToBigDecimal(Object obj) {
        return convertToBigDecimal(obj, null);
    }

    public static BigDecimal convertToBigDecimal(Object obj, BigDecimal defaultValue) {
        if (obj == null || obj.toString().isEmpty() || "null".equals(obj.toString().toLowerCase(Locale.ROOT))) {
            return defaultValue;
        } else if (obj instanceof Boolean) {
            return (Boolean)obj ? BigDecimal.ONE : BigDecimal.ZERO;
        } else if (obj instanceof Long) {
            return BigDecimal.valueOf((long)obj);
        } else if (obj instanceof Integer) {
            return BigDecimal.valueOf((long)((Integer)obj));
        } else if (obj instanceof Double) {
            return BigDecimal.valueOf((Double)obj);
        } else if (obj instanceof BigInteger) {
            return new BigDecimal((BigInteger)obj);
        } else if (obj instanceof String) {
            return new BigDecimal((String) obj);
        } else {
            return BigDecimal.valueOf(Double.parseDouble(obj.toString()));
        }
    }

    public static BigDecimal convertToBigDecimalInclDate(Object obj) {
        return convertToBigDecimalInclDate(obj, null);
    }

    public static BigDecimal convertToBigDecimalInclDate(Object obj, BigDecimal defaultValue) {
        if (obj == null || obj.toString().isEmpty() || "null".equals(obj.toString().toLowerCase(Locale.ROOT))) {
            return defaultValue;
        } else if (obj instanceof Boolean) {
            return (Boolean)obj ? BigDecimal.ONE : BigDecimal.ZERO;
        } else if (obj instanceof Long) {
            return BigDecimal.valueOf((long)obj);
        } else if (obj instanceof Integer) {
            return BigDecimal.valueOf((long)((Integer)obj));
        } else if (obj instanceof Double) {
            return BigDecimal.valueOf(((Double)obj).longValue());
        } else if (obj instanceof String) {
            try {
                return new BigDecimal((String) obj);
            } catch (NumberFormatException e) {
                return tryReadDate((String)obj, FormatUtils.FMT_ISO_DATE_FORMAT_OFFSET.get());
            }
        } else {
            return BigDecimal.valueOf((long)(Double.parseDouble(obj.toString())));
        }
    }

    public static BigDecimal tryReadDate(String obj, DateTimeFormatter formatter) {
        if (obj.length() == 10) {
            LocalDate date = LocalDate.parse((String) obj, FormatUtils.FMT_DAY_FORMAT.get());
            return BigDecimal.valueOf(date.atStartOfDay().toInstant(ZoneOffset.UTC).toEpochMilli());
        } else {
            try {
                ZonedDateTime date = ZonedDateTime.parse(obj, FormatUtils.FMT_ISO_DATE_FORMAT_OFFSET.get()).withZoneSameInstant(zoneUTC);
                return BigDecimal.valueOf(date.toInstant().toEpochMilli());
            } catch (Exception e) {
                try {
                    ZonedDateTime date = ZonedDateTime.parse(obj, FormatUtils.FMT_ISO_DATE_FORMAT.get()).withZoneSameInstant(zoneUTC);
                    return BigDecimal.valueOf(date.toInstant().toEpochMilli());
                } catch (Exception e2) {
                    LocalDateTime date = LocalDateTime.parse(obj, FormatUtils.FMT_DATE_FORMAT.get());
                    return BigDecimal.valueOf(date.toInstant(ZoneOffset.UTC).toEpochMilli());
                }
            }
        }
    }

    public static String convertToString(Object obj) {
        return convertToString(obj, null);
    }

    public static String convertToString(Object obj, String defaultValue) {
        if (obj == null) {
            return defaultValue;
        } else if (obj instanceof String) {
            return (String)obj;
        } else {
            return obj.toString();
        }
    }

    public static Boolean convertToBoolean(Object obj) {
        return convertToBoolean(obj, null);
    }

    public static Boolean convertToBoolean(Object obj, Boolean defaultValue) {
        if (obj instanceof String && "false".equals(obj.toString().toLowerCase(Locale.ROOT))) {
            return false;
        } else if (obj instanceof String && "true".equals(obj.toString().toLowerCase(Locale.ROOT))) {
            return true;
        } else {
            Long numeric = convertToLong(obj);
            return numeric != null ? numeric != 0 : (defaultValue != null ? defaultValue : false);
        }
    }
}