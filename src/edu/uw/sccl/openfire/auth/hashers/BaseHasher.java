package edu.uw.sccl.openfire.auth.hashers;

import edu.uw.sccl.openfire.auth.Algorithm;
import edu.uw.sccl.openfire.auth.HashException;

import java.security.SecureRandom;

public abstract class BaseHasher {
    protected final static int SALT_LENGTH = 12;
    protected final static char[] SALT_ACCEPTED_CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();

    public abstract Algorithm getAlgorithm();

    public abstract String encode(String password, String salt)
            throws HashException;

    public abstract boolean verify(String password, String encoded)
            throws HashException;

    public String getSalt() {
        SecureRandom random = new SecureRandom();
        char[] salt = new char[SALT_LENGTH];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = SALT_ACCEPTED_CHARS[random.nextInt(SALT_ACCEPTED_CHARS.length)];
        }
        return new String(salt);
    }
}
