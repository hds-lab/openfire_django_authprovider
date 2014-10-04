package edu.uw.sccl.openfire.auth.hashers;

import edu.uw.sccl.openfire.auth.Algorithm;
import edu.uw.sccl.openfire.auth.HashException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.xml.bind.DatatypeConverter;

public class PBKDF2SHA256PasswordHasher extends BaseHasher {
    public final static int iterations = 12000;

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.pbkdf2_sha256;
    }


    protected GeneralDigest getDigest() {
        return new SHA256Digest();
    }


    private String getEncodedHash(String password, String salt, int iterations) {
        GeneralDigest digest = getDigest();

        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(digest);
        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()),
                salt.getBytes(), iterations);
        KeyParameter key = (KeyParameter)generator.generateDerivedMacParameters(digest.getDigestSize() * 8); //# of bits

        byte[] dk = key.getKey();
        return DatatypeConverter.printBase64Binary(dk);
    }

    @Override
    public String encode(String password, String salt)
            throws HashException {
        return encode(password, salt, iterations);
    }

    public String encode(String password, String salt, int iterations)
            throws HashException {
        // returns hashed password, along with algorithm, number of iterations and salt
        String hash = getEncodedHash(password, salt, iterations);
        return String.format("%s$%d$%s$%s", getAlgorithm().toString(), iterations, salt, hash);
    }

    @Override
    public boolean verify(String password, String encoded)
            throws HashException {

        String[] parts = encoded.split("\\$");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Wrong hash format");
        }

        Integer iterations = Integer.parseInt(parts[1]);
        String salt = parts[2];

        String hash = encode(password, salt, iterations);
        return hash.equals(encoded);
    }
}
