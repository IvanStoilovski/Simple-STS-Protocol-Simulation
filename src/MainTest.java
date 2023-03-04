import javax.crypto.*;
import java.security.*;

public class MainTest {
    public static void main(String[] args) throws NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        User a = new User("Alice");
        User b = new User("Bob");
        STSImplementation impl = new STSImplementation(a, b);
        impl.implement();
    }
}
