import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

public class User {
    private static final BigInteger a = new BigInteger("50256");
    private final String name;
    private final PrivateKey privateKey;
    public PublicKey publicKey;
    private Integer mine;
    private BigInteger aMine;
    private BigInteger aOther;
    private byte[] secretKey;
    byte[] hashedVal;
    public static HashMap<String, PublicKey> keyMap = new HashMap<>();

    public User(String name) throws NoSuchAlgorithmException {
        this.name = name;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
        keyMap.putIfAbsent(name, publicKey);
    }

    public byte[] getHashedVal() {
        return hashedVal;
    }

    public void setHashedVal(byte[] hashedVal) {
        this.hashedVal = hashedVal;
    }

    public BigInteger get_a_Other() {
        return aOther;
    }

    public void set_a_Other(BigInteger aOther) {
        this.aOther = aOther;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public String getName() {
        return this.name;
    }

    public void setSecretKey(byte[] secretKey) {
        this.secretKey = secretKey;
    }

    public BigInteger getaMine() {
        return aMine;
    }

    public void setaMine(BigInteger aMine) {
        this.aMine = aMine;
    }

    public Integer getMine() {
        return mine;
    }

    public void setMine(Integer mine) {
        this.mine = mine;
    }

    public void printKey() {
        SecretKey sk = new SecretKeySpec(this.getSecretKey(), 0, 32, "AES");
        byte[] encoded = sk.getEncoded();
        StringBuilder sb = new StringBuilder();
        for (byte b : encoded)
            sb.append(String.format("%02X ", b));
        System.out.println(sb);

    }

    public Integer produceRandom() {
        Random rand = new Random();
        return rand.nextInt(100);
    }

    public byte[] hashA(BigInteger a, BigInteger b) throws NoSuchAlgorithmException {
        ByteBuffer bb = ByteBuffer.allocate(a.toByteArray().length + b.toByteArray().length);
        bb.put(a.toByteArray()).put(b.toByteArray());
        byte[] as = bb.array();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(as);
    }

    public byte[] sign(User u, byte[] arr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipherHashed = Cipher.getInstance("RSA");
        encryptCipherHashed.init(Cipher.ENCRYPT_MODE, u.getPrivateKey());
        return encryptCipherHashed.doFinal(arr);
    }

    public byte[] encrypt(User u, byte[] arr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey sk = new SecretKeySpec(u.getSecretKey(), 0, 32, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sk);
        return cipher.doFinal(arr);
    }

    public byte[] decrypt(User u, byte[] arr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey secretKey1 = new SecretKeySpec(u.getSecretKey(), 0, 32, "AES");
        Cipher cipher2 = Cipher.getInstance("AES");
        cipher2.init(Cipher.DECRYPT_MODE, secretKey1);
        return cipher2.doFinal(arr);
    }

    public byte[] checkUserAuth(User u, byte[] arr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        PublicKey otherUser = keyMap.get(u.getName());
        decryptCipher.init(Cipher.DECRYPT_MODE, otherUser);
        return decryptCipher.doFinal(arr);
    }

    public CommPacket communicate() {
        Integer x = produceRandom();
        this.setMine(x);
        BigInteger ax = a.pow(x);
        this.setaMine(ax);
        return new CommPacket(ax, this);
    }

    public CommPacket receivedComm(CommPacket p) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        BigInteger ax = p.PowA;
        this.set_a_Other(ax);
        User other = p.user;
        Integer k = produceRandom();
        this.setMine(k);
        BigInteger ay = a.pow(k);
        this.setaMine(ay);
        BigInteger secretKey = ax.pow(k);
        this.setSecretKey(secretKey.toByteArray());

        //Hash a^x and a^y
        byte[] hash = hashA(this.getaMine(), this.get_a_Other());
        this.setHashedVal(hash);
        //Hash a^x and a^y

        //Sign hashed a^x and a^y
        byte[] hashedValues = sign(this, hash);
        //Sign hashed a^x and a^y

        //Encrypt signed and hashed a^x and a^y with the secret key
        byte[] encryptedSignature = encrypt(this, hashedValues);
        //Encrypt signed and hashed a^x and a^y with the secret key
        return new CommPacket(encryptedSignature, ay, this);
    }

    public CommPacket receiveFirstAnswer(CommPacket p) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UserNotAuthenticatedException {
        BigInteger ay = p.PowA;
        User other = p.user;
        byte[] enc = p.encrypted;
        BigInteger secretKey = ay.pow(this.getMine());
        this.setSecretKey(secretKey.toByteArray());
        this.set_a_Other(ay);

        //Decrypt message from other user
        byte[] decryptedSignature = decrypt(this, enc);
        //Decrypt message from other user

        //Decrypt signed
        byte[] decryptedMessageBytes = checkUserAuth(other, decryptedSignature);
        //Decrypt signed

        //Hash a^x and a^y again to check
        byte[] hashed2 = hashA(this.get_a_Other(), this.getaMine());
        this.setHashedVal(hashed2);
        //Hash a^x and a^y again to check

        if (!Arrays.equals(decryptedMessageBytes, hashed2))
            throw new UserNotAuthenticatedException("User could not be authenticated!");

        //make an encrypted packet signed by the initiator
        byte[] signedNew = sign(this, hashed2);
        byte[] encryptNew = encrypt(this, signedNew);
        return new CommPacket(this, encryptNew);
        // authLast(this,encryptNew);
    }

    public void authLast(CommPacket p) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, UserNotAuthenticatedException {
        User other = p.user;
        byte[] msg = p.encrypted;
        byte[] decrypted = decrypt(this, msg);
        byte[] hash = checkUserAuth(other, decrypted);
        if (!Arrays.equals(hash, this.getHashedVal()))
            throw new UserNotAuthenticatedException("User could not be authenticated!");
        else
            System.out.println("Key exchanged successfully!");
    }
}
