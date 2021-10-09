package ru.voskhod;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hasher {
  static   MessageDigest digest2001;
  static   MessageDigest digest2012;

    static {
        try {
            digest2001 = MessageDigest.getInstance("GOST3411");
            digest2012 = MessageDigest.getInstance("GOST3411_2012_256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    static public byte[] getHash2012(byte[] data) {
        digest2012.update(data);
        return digest2012.digest();
    }
    static public byte[] getHash2001(byte[] data) {
        digest2001.update(data);
        return digest2001.digest();
    }




}
