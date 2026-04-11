package com.devpath.support;

public final class H2SequenceFunctions {

  private H2SequenceFunctions() {}

  public static String pgGetSerialSequence(String tableName, String columnName) {
    return tableName + "_" + columnName + "_seq";
  }

  public static Long setval(String sequenceName, Long value) {
    return value;
  }

  public static Long setval(String sequenceName, Long value, Boolean isCalled) {
    return value;
  }
}
