package msa.service.auth.util;

import msa.service.auth.domain.exception.InternalServerException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {

    public static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(input.getBytes());

            StringBuilder sb = new StringBuilder();
            for (byte b: hash) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new InternalServerException("HashUtil.sha256(): sha-256 not supported.");
        }
    }

}
