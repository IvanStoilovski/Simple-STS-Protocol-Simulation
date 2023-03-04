import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class STSImplementation {
    User user1;
    User user2;

    public STSImplementation(User u1, User u2) {
        this.user1 = u1;
        this.user2 = u2;
    }

    public void implement() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        try {
            user2.authLast(user1.receiveFirstAnswer(user2.receivedComm(user1.communicate())));
        } catch (UserNotAuthenticatedException e) {
            System.out.println(e.getMessage());
        }
        System.out.println("User "+user1.getName()+"s' key: ");
        user1.printKey();
        System.out.println("User "+user2.getName()+"s' key: ");
        user1.printKey();
    }
}