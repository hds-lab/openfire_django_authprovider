package edu.uw.sccl.openfire.auth;

/*
The code below is from https://gist.github.com/lukaszb/1af1bd4233326e37a8a0

I have modified it to work on java < 1.8 (swapping DatatypeConverter for Base64)
  see http://stackoverflow.com/questions/469695/decode-base64-data-in-java

I have added constructors to make the algorithm and iterations configurable.

Note the full list of hash algorithms supported by django by default:
PASSWORD_HASHERS = (
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA256PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    'django.contrib.auth.hashers.BCryptPasswordHasher',
    'django.contrib.auth.hashers.SHA1PasswordHasher',
    'django.contrib.auth.hashers.MD5PasswordHasher',
    'django.contrib.auth.hashers.CryptPasswordHasher',
)
--------------------------------------------- */

/* Example implementation of password hasher similar on Django's PasswordHasher
 * Requires Java8 (but should be easy to port to older JREs)
 * Currently it would work only for pbkdf2_sha256 algorithm
 *
 * Django code: https://github.com/django/django/blob/1.6.5/django/contrib/auth/hashers.py#L221
 */

import edu.uw.sccl.openfire.auth.hashers.BaseHasher;

public class Hasher {
    private static final String UNUSABLE_PASSWORD_PREFIX = "!";
    private static final Algorithm DEFAULT_ALGORITHM = Algorithm.pbkdf2_sha256;
    private final Algorithm algorithm;

    public Hasher() {
        algorithm = DEFAULT_ALGORITHM;
    }

    public Hasher(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Checks if the given password is usable.
     * @param encoded
     * @return
     */
    private boolean isPasswordUsable(String encoded) {
        if (encoded == null || encoded.length() == 0 || encoded.startsWith(UNUSABLE_PASSWORD_PREFIX)) {
            return false;
        }

        return true;
    }

    /**
     * Checks whether a given password hashes to the same hashed password.
     *
     * See django.contrib.auth.hashers.check_password
     *
     * @param password
     * @param hashedPassword
     * @return
     */
    public boolean checkPassword(String password, String hashedPassword)
        throws UnsupportedAlgorithmException, HashException {
        if (password == null || !isPasswordUsable(hashedPassword)) {
            return false;
        }

        BaseHasher hasher = Algorithm.identifyHasher(hashedPassword).getHasher();

        try {
            return hasher.verify(password, hashedPassword);
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public String makePassword(String password)
            throws HashException {
        return makePassword(password, algorithm);
    }

    public String makePassword(String password, Algorithm algorithm)
            throws HashException {
        return makePassword(password, null, algorithm);
    }

    public String makePassword(String password, String salt)
            throws HashException {
        return makePassword(password, salt, algorithm);
    }

    public String makePassword(String password, String salt, Algorithm algorithm)
        throws HashException {

        BaseHasher hasher = algorithm.getHasher();

        if (salt == null) {
            salt = hasher.getSalt();
        }

        return hasher.encode(password, salt);
    }


}
