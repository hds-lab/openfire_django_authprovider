package edu.uw.sccl.openfire.auth.hashers;

import edu.uw.sccl.openfire.auth.Algorithm;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;

/**
 * Created by mjbrooks on 10/4/2014.
 */
public class PBKDF2SHA1PasswordHasher extends PBKDF2SHA256PasswordHasher {
    @Override
    protected GeneralDigest getDigest() {
        return new SHA1Digest();
    }

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.pbkdf2_sha1;
    }
}
