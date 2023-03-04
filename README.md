# Simple-STS-Protocol-Simulation
### This is a crude and simple simulation of the STS (Station-To-Station) protocol. In public-key cryptography the Station-to-Station (STS) protocol is a cryptographic key agreement scheme. The protocol is based on classic Diffie–Hellman, and provides mutual key and entity authentication.Unlike the classic Diffie–Hellman, which is not secure against a man-in-the-middle attack, this protocol assumes that the parties have signature keys, which are used to sign messages, thereby providing security against man-in-the-middle attacks.

 ***For more information about this protocol, click [here](https://en.wikipedia.org/wiki/Station-to-Station_protocol).***
 
 ***A diagram of the protocol is shown [here](https://www.researchgate.net/profile/Alexandre-Braga-3/publication/273458481/figure/fig2/AS:614092771446839@1523422534828/Station-to-Station-STS-protocol.png).***

- ### For simplicity in the documentation below, the user that initiates communication will be referred to as ***Alice***, while the user that receives the initiation for communication will be referred to as ***Bob***.

- ### In this simulation of the STS protocol, we assume that the number ***a*** is known/given in advance and the number ***a*** is static.

## This project is a simple and crude simulation of the aforementioned protocol. This simulation is achieved with **5 classes:** 

**1. User, which consists of 24 methods:**
  - **A constructor with parameters.**
  - **12 Setters/Getters.**
  - **void printKey**
    - A method prints the exchanged symmetric key.
   - **Integer produceRandom**
      - A method generates a random number.
   - **byte[ ] hashA**
      - A method that transforms two ***BigInteger*** numbers into ***byte arrays*** and then hashes them using ***SHA-256***.  
   - **byte[ ] sign**
      - A method that uses a user's own private asymmetric key to encrypt a given message, thus signing the message.
   - **byte[ ] encrypt**
      - A method that uses the exchanged symmetric key between the users to encrypt a message.
   - **byte[ ] decrypt**
      - A method that uses the exchanged symmetric key between the users to decrypt a message.
   - **byte [ ] checkUserAuth**
      - A method that decrypts a given message sent by a ***user***, using the same ***user's*** assymetric ***public key***, thus verifying that the message was sent by the intended ***user***, as the message will be encrypted (signed) using the ***user's*** own assymetric ***private key***.
   - **CommPacket communicate**
      - A method that is used when ***Alice*** wants to initiate communication with ***Bob***. In this method, Alice generates a random number ***x*** using the ***produceRandom*** method. Next, ***Alice*** uses the random number ***x*** as an exponent when applying the mathematical exponentiation function to the number ***a***: (***a^x***).
   - **CommPacket receivedcomm**
      - This method is used when ***Bob*** receives a packet from ***Alice*** when ***Alice*** first initiates communication. ***Bob*** firstly generates his own random number ***y*** using the ***generateRandom*** method. Next, ***Bob*** uses the random number ***y*** as an exponent when applying the mathematical exponentiation function to the number ***a***: (***a^y***). ***Bob*** also uses his random number to exponate the number ***Alice*** has sent him ***a^x***: ***(a^x)^y***. With this, the symmetric key (***a^xy***) is formed. Next, ***Bob*** uses the ***hashA*** function to hash the numbers ***a^x*** (the number sent to ***Bob*** by ***Alice***) and ***a^y*** (the number ***Bob*** calculates). Next, ***Bob*** signs the hashed numbers using the ***sign*** method. Finally, ***Bob*** encrypts this message with the newly calculated symmetric key. ***Bob*** sends this array along with his ***a^y*** number to ***Alice***.   
   - **CommPacket receiveFirstAnswer**
      - This method is used when ***Alice*** gets an answer from ***Bob***. ***Alice*** uses ***Bob***'s ***a^y*** number to calculate the symmetric key by exponating ***a^y*** with her number ***x***: ***(a^y)^x***. Next, ***Alice*** decrypts the message sent by ***Bob*** encrypted with the symmetric key. Next, ***Alice*** uses ***Bob***'s assymetric public key to authenticate the singed message by ***Bob***. As a result of the authentication operation, ***Alice*** has the hashed numbers ***(a^x,a^y)*** received from ***Bob***. Finally, ***Alice*** hashes ***(a^x,a^y)*** on her own and if her hashed value doesn't match with ***Bob***'s hashed value, the operation stops (an exception is thrown). If the hashed values match, ***Bob*** is authenticated and ***Alice*** sends ***Bob*** a packet (message) in the same fashion as ***Bob*** does in the ***receivedComm*** method.
   - **void authLast**
      - This method is used when ***Bob*** receives a confirmation from ***Alice***. ***Bob*** authenticates ***Alice*** by firstly decrypting the ***Alice***'s message with the symmetric key. Next, ***Bob*** authenticates ***Alice*** by decrypting her signed message with her assymetric public key. As a result of this operation, ***Bob*** receives the hashed numbers ***(a^x,a^y)*** that ***Alice*** has calculated. Lastly, ***Bob*** comppares this value with his own hashed value of the numbers ***(a^x,a^y)***. If both values match, ***Alice*** is authenticated and the symmetric key is successfully exchanged. If the hashed values don't match, an exception is thrown.

**2. STSImplementation**
  - This class simulates the process of the STS protocol. In the ***implement*** method of this class we simulate a symetric key exchange between two users by calling corresponding methods created un the ***User*** class.

**3. CommPacket**
  - This class is used to simulate a packet which is sent between communicating users in the process of the symetric key exchange. 
  
**4. UserNotAuthenticatedException**
  - An exception class.
  
**5. MainTest**
  - The main class used to input users manually and run the program.
  
  
  
### Basic STS ( taken from [wikipedia](https://en.wikipedia.org/wiki/Station-to-Station_protocol) )  (note: in the following example ***g*** is used instead of ***a*** which  is used in the simulation). Supposing all setup data has been shared, the STS protocol proceeds as follows. If a step cannot be completed, the protocol immediately stops. All exponentials are in the group specified by p.
1. Alice → Bob : gx
2. Alice ← Bob : gy, EK(SB(gy, gx))
3. Alice → Bob : EK(SA(gx, gy))

