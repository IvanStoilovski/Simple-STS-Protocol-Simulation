import java.math.BigInteger;

public class CommPacket {
    byte[] encrypted;
    BigInteger PowA;
    User user;

    public CommPacket(BigInteger a, User u) {
        this.PowA = a;
        encrypted = null;
        this.user = u;
    }

    public CommPacket(byte[] msg, BigInteger a, User u) {
        this.encrypted = msg;
        this.PowA = a;
        this.user = u;
    }

    public CommPacket(User u, byte[] msg) {
        this.PowA = null;
        this.encrypted = msg;
        this.user = u;
    }
}
