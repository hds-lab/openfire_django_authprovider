package edu.uw.sccl.openfire.auth;

import edu.uw.sccl.openfire.auth.hashers.BaseHasher;
import edu.uw.sccl.openfire.auth.hashers.PBKDF2SHA1PasswordHasher;
import edu.uw.sccl.openfire.auth.hashers.PBKDF2SHA256PasswordHasher;

/**
 * Supported hashing algorithms
 */
public enum Algorithm {
    pbkdf2_sha256(new PBKDF2SHA256PasswordHasher()),
    pbkdf2_sha1(new PBKDF2SHA1PasswordHasher());
    //bcrypt_sha256,
    //bcrypt,
//    sha1(hasher),
//    md5(hasher),
//    unsalted_md5(hasher),
//    crypt(hasher);

    private final BaseHasher hasher;

    Algorithm(BaseHasher hasher) {
        this.hasher = hasher;
    }

    public BaseHasher getHasher() {
        return this.hasher;
    }

    /**
     * Determines the algorithm used to create a hash.
     * <p/>
     * See django.contrib.auth.hashers.identify_hasher
     *
     * @param encoded
     * @return
     */
    public static Algorithm identifyHasher(String encoded)
            throws UnsupportedAlgorithmException {
        // Ancient versions of Django created plain MD5 passwords and accepted
        // MD5 passwords with an empty salt.
        if ((encoded.length() == 32 && encoded.indexOf('$') < 0) ||
                (encoded.length() == 37 && encoded.startsWith("md5$$"))) {
            throw new UnsupportedAlgorithmException("Django hash type 'unsalted_md5' is not supported");

            // Ancient versions of Django accepted SHA1 passwords with an empty salt.
        } else if (encoded.length() == 46 && encoded.startsWith("sha1$$")) {
            //but we don't support this type
            throw new UnsupportedAlgorithmException("Django hash type 'unsalted_sha1' is not supported");
        } else {
            String algStr = encoded.substring(0, encoded.indexOf('$'));
            try {
                return Algorithm.valueOf(algStr);
            }catch (IllegalArgumentException e) {
                throw new UnsupportedAlgorithmException("Django hash type '" + algStr + "' is not supported");
            }
        }
    }

    }