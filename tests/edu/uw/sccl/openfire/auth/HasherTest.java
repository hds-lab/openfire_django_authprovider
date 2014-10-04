package edu.uw.sccl.openfire.auth;

import junit.framework.Assert;
import junit.framework.TestCase;

public class HasherTest extends TestCase {

    // Following examples can be generated at any Django project:
    //
    //  >>> from django.contrib.auth.hashers import make_password
    //  >>> make_password('mystery', hasher='pbkdf2_sha256')  # salt would be randomly generated
    //  'pbkdf2_sha256$10000$HqxvKtloKLwx$HdmdWrgv5NEuaM4S6uMvj8/s+5Yj+I/d1ay6zQyHxdg='
    //  >>> make_password('mystery', salt='mysalt', hasher='pbkdf2_sha256')
    //  'pbkdf2_sha256$10000$mysalt$KjUU5KrwyUbKTGYkHqBo1IwUbFBzKXrGQgwA1p2AuY0='
    //
    //
    // mystery
    // pbkdf2_sha256$10000$qx1ec0f4lu4l$3G81rAm/4ng0tCCPTrx2aWohq7ztDBfFYczGNoUtiKQ=
    //
    // s3cr3t
    // pbkdf2_sha256$10000$BjDHOELBk7fR$xkh1Xf6ooTqwkflS3rAiz5Z4qOV1Jd5Lwd8P+xGtW+I=
    //
    // puzzle
    // pbkdf2_sha256$10000$IFYFG7hiiKYP$rf8vHYFD7K4q2N3DQYfgvkiqpFPGCTYn6ZoenLE3jLc=
    //
    // riddle
    // pbkdf2_sha256$10000$A0S5o3pNIEq4$Rk2sxXr8bonIDOGj6SU4H/xpjKHhHAKpFXfmNZ0dnEY=

    public void testCheckPassword() throws Exception {
        Hasher hasher = new Hasher();

        assertTrue(hasher.checkPassword("mystery", "pbkdf2_sha256$10000$qx1ec0f4lu4l$3G81rAm/4ng0tCCPTrx2aWohq7ztDBfFYczGNoUtiKQ="));
        assertTrue(hasher.checkPassword("mystery", "pbkdf2_sha256$10000$mysalt$KjUU5KrwyUbKTGYkHqBo1IwUbFBzKXrGQgwA1p2AuY0="));  // custom salt
        assertTrue(hasher.checkPassword("s3cr3t", "pbkdf2_sha256$10000$BjDHOELBk7fR$xkh1Xf6ooTqwkflS3rAiz5Z4qOV1Jd5Lwd8P+xGtW+I="));
        assertTrue(hasher.checkPassword("puzzle", "pbkdf2_sha256$10000$IFYFG7hiiKYP$rf8vHYFD7K4q2N3DQYfgvkiqpFPGCTYn6ZoenLE3jLc="));
        assertTrue(hasher.checkPassword("riddle", "pbkdf2_sha256$10000$A0S5o3pNIEq4$Rk2sxXr8bonIDOGj6SU4H/xpjKHhHAKpFXfmNZ0dnEY="));

        assertFalse(hasher.checkPassword("mystery", "pbkdf2_sha256$10001$Qx1ec0f4lu4l$3G81rAm/4ng0tCCPTrx2aWohq7ztDBfFYczGNoUtiKQ="));
        assertFalse(hasher.checkPassword("mystery", "pbkdf2_sha256$10001$qx1ec0f4lu4l$3G81rAm/4ng0tCCPTrx2aWohq7ztDBfFYczGNoUtiKQ="));
        assertFalse(hasher.checkPassword("mystery", "pbkdf2_sha256$10000$qx7ztDBfFYczGNoUtiKQ="));
        assertFalse(hasher.checkPassword("s3cr3t", "pbkdf2_sha256$10000$BjDHOELBk7fR$foobar"));
        assertFalse(hasher.checkPassword("puzzle", "pbkdf2_sha256$10000$IFYFG7hiiKYP$rf8vHYFD7K4q2N3DQYfgvkiqpFPGCTYn6ZoenLE3jLcX"));

        assertTrue(hasher.checkPassword("mystery", "pbkdf2_sha1$10000$qx1ec0f4lu4l$3G81rAm/4ng0tCCPTrx2aWohq7ztDBfFYczGNoUtiKQ="));
        assertTrue(hasher.checkPassword("testing", "pbkdf2_sha1$12000$S5JAv3fiOHib$ntIRwExfIadsbkmdudq/8sJ2z0g="));
        assertTrue(hasher.checkPassword("testing", "pbkdf2_sha256$12000$JxAjIihbx3Qt$ru2fy3S0pnWHvdt/L67OTyRC9Ty8yWce0Rapjb+shRg="));
    }

    public void testCheckPassword_unusableHash() throws Exception {
        Hasher hasher = new Hasher();
        assertFalse(hasher.checkPassword("foo", ""));
        assertFalse(hasher.checkPassword("testing", "!pbkdf2_sha256$12000$JxAjIihbx3Qt$ru2fy3S0pnWHvdt/L67OTyRC9Ty8yWce0Rapjb+shRg="));
    }

    public void testCheckPassword_unsupportedAlgorithm() throws Exception {
        Hasher hasher = new Hasher();

        String[][] testCases = new String[][] {
                new String[] {"mystery", "pbkdf2_md5$10000$qx1ec0f4lu4l$3G81rAm/4ng0tCCPTrx2aWohq7ztDBfFYczGNoUtiKQ="},
                new String[] {"testing", "sha1$xkwQQTGRboLE$e716a887d688787c1da5f4982e22d291d806082c"},
                new String[] {"testing", "md5$bZILkHQRb2d2$7d969c3cae120409dfac105ee0863618"},
                new String[] {"testing", "ae2b1fca515949e5d54fb22b8ed95575"}
        };

        for (int i = 0; i < testCases.length; i++) {
            boolean thrown = false;
            try {
                hasher.checkPassword(testCases[i][0], testCases[i][1]);
            } catch (UnsupportedAlgorithmException e) {
                thrown = true;
            }
            assertTrue("Test case " + i, thrown);
        }
    }


}