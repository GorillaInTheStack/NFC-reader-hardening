package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;
import java.util.UUID;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /**
     * Default keys are stored in res/values/secrets.xml
     **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();
    private static final String applicationTag = "6666";

    /**
     * TODO: Change these according to your design. Diversify the keys.
     */
    private static final byte[] authenticationKey = defaultAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private final Boolean isValid = true; //should be changed accordingly. Used elsewhere.
    private final int remainingUses = 5; //default.
    private final int expiryTime =
            (int) ((new Date()).getTime() / 1000 / 60) + 1440; //default, 24h in minutes.

    private static String infoToShow = "-"; // Use this to show messages

    /**
     * Create a new ticket
     */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /**
     * After validation, get ticket status: was it valid or not?
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * After validation, get the number of remaining uses
     */
    public int getRemainingUses() {
        return remainingUses;
    }

    /**
     * After validation, get the expiry time
     */
    public int getExpiryTime() {
        return expiryTime;
    }

    /**
     * After validation/issuing, get information
     */
    public static String getInfoToShow() {
        return infoToShow;
    }

    /**
     * Issue new tickets
     * <p>
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        /*
          How the card memory is expected to be after issuing the card:

          Page 0: UID.
          Page 1: UID.
          Page 2: first byte contains UID check byte, last 2 bytes are Lock bits.
          Page 3: non-reset-able OTP.

          .... First Application Page ....
          Page 4: program tag => applicationTag.
          Page 5-6: empty in case we want to add our own ID.
          Page 7: number of uses => int uses.
          Page 8: number of days the ticket is valid from issue date => int daysValid.
          Page 9-13: issue date
          Page 14-18: HMAC

          Page 39:
          .... Last Application Page ....

          Page 41: 16-bit counter.
          Page 42: Auth0 in byte 0.
          Page 43: Auth1 in byte 0.
          Page 44-47: Auth key (non-readable)

         */


        // Check the application tag
        byte[] cardApplicationTag = new byte[4];
        boolean checkApplicationTag = utils.readPages(4, 1, cardApplicationTag, 0);

        // Set information to show for the user
        if (false && checkApplicationTag && applicationTag.equals(new String(cardApplicationTag))) {
            infoToShow = "Ticket already issued!";
            return false;

        } else {

            byte[] cardUIDFull = new byte[8];
            boolean checkCardUID = utils.readPages(0, 2, cardUIDFull, 0);
            if (!checkCardUID) {
                infoToShow = "Unable to read UID!";
                Utilities.log("ERROR: problems while reading UID in issue().", true);
                return false;
            }
            byte[] cardUID = new byte[7];
            // The UID is a 7 byte serial number located in first 3 bytes of page 0 and all of page 1
            System.arraycopy(Arrays.copyOfRange(cardUIDFull, 0, 3), 0, cardUID, 0, 3);
            System.arraycopy(Arrays.copyOfRange(cardUIDFull, 4, 8), 0, cardUID, 3, 4);
            Utilities.log("INFO: Card UID " + convertByteArrayToHex(cardUID), false);

            String diversifiedAuthKey = createDiversifiedKey(new String(authenticationKey), convertByteArrayToHex(cardUID));
            String diversifiedMacKey = createDiversifiedKey(new String(hmacKey), convertByteArrayToHex(cardUID));

            if (diversifiedAuthKey == null || diversifiedMacKey == null) {
                infoToShow = "Error generating keys!";
                Utilities.log("ERROR: problems while generating keys in issue().", true);
                return false;
            }
            Utilities.log("INFO: Keys generated successfully in method issue()!", false);

            // Authenticate
            boolean res;
            // try first with default, if it doesn't work try with diversified
            // in case a tear occurred before setting the tag
            res = utils.authenticate(defaultAuthenticationKey);
            if (!res) {
                res = utils.authenticate(diversifiedAuthKey.getBytes());
                if (!res) {
                    Utilities.log("Authentication failed in issue()", true);
                    infoToShow = "Authentication failed";
                    return false;
                }
            }
            Utilities.log("INFO: Authentication successful in method issue()!", false);

            // erase card content
            boolean cardErased = utils.eraseMemory();
            if (!cardErased) {
                infoToShow = "Cannot erase card!";
                Utilities.log("ERROR: problems while erasing memory in issue().", true);
                return false;
            }
            Utilities.log("INFO: Card erased successfully in method issue()!", false);

            // write number of uses
            boolean usesWritten = utils.writePages(intToByteArray(uses), 0, 7, 1);
            if (!usesWritten) {
                infoToShow = "Unable to write number of uses!";
                Utilities.log("ERROR: problems while writing uses in issue().", true);
                return false;
            }
            Utilities.log("INFO: Number of uses written successfully in method issue()!", false);

            // write number of days valid
            boolean daysValidWritten = utils.writePages(intToByteArray(daysValid), 0, 8, 1);
            if (!daysValidWritten) {
                infoToShow = "Unable to write number of days valid!";
                Utilities.log("ERROR: problems while writing days valid in issue().", true);
                return false;
            }
            Utilities.log("INFO: Number of valid days written successfully in method issue()!", false);

            // Generate and write HMAC which initially is HMAC("rides||daysValid")
            macAlgorithm.setKey(diversifiedMacKey.getBytes());
            byte[] mac = macAlgorithm.generateMac((uses + "||" + daysValid).getBytes());
            boolean writeHMAC = utils.writePages(mac, 0, 14, 5);
            if (!writeHMAC) {
                infoToShow = "Unable to write HMAC!";
                Utilities.log("ERROR: problems while writing HMAC in issue().", true);
                return false;
            }
            Utilities.log("INFO: HMAC written successfully in method issue()!", false);

            boolean writeAuthKey = utils.writePages(diversifiedAuthKey.getBytes(), 0, 44, 4);
            if (!writeAuthKey) {
                infoToShow = "Unable to write new Auth Key!";
                Utilities.log("ERROR: problems while writing Auth Key in issue().", true);
                return false;
            }
            Utilities.log("INFO: Auth Key set successfully in method issue()!", false);

            // Setting Auth1 to 0h restrict read and write
            boolean auth1Written = utils.writePages(intToByteArray(0), 0, 43, 1);
            if (!auth1Written) {
                infoToShow = "Failed to configure Auth1!";
                Utilities.log("ERROR: problems while configuring Auth1 in issue().", true);
                return false;
            }
            Utilities.log("INFO: Auth1 configured successfully in method issue()!", false);


            // Setting Auth0 to 2bh to protect Auth1 and Key
            byte[] page42 = new BigInteger("2b000000", 16).toByteArray();
            boolean auth0Written = utils.writePages(page42, 0, 42, 1);
            if (!auth0Written) {
                infoToShow = "Failed to configure Auth0!";
                Utilities.log("ERROR: problems while configuring Auth0 in issue().", true);
                return false;
            }
            Utilities.log("INFO: Auth0 configured successfully in method issue()!", false);


            boolean tagWritten = utils.writePages(applicationTag.getBytes(), 0, 4, 1);
            if (!tagWritten) {
                infoToShow = "Unable to write tag!";
                Utilities.log("ERROR: problems while writing Tag in issue().", true);
                return false;
            }

            Utilities.log("INFO: Ticket issued successfully!", false);

        }

        return true;
    }

    /**
     * Use ticket once
     * <p>
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        //Check tag, if not there return immediately.
        byte[] cardApplicationTag = new byte[4];
        boolean readSuccessful = utils.readPages(4, 1, cardApplicationTag, 0);
        if (!readSuccessful || !applicationTag.equals(new String(cardApplicationTag))) {
            infoToShow = "Ticket was not issued correctly!";
            System.err.println("ERROR: problems while reading tag in method use().");
            return false;

        }
        System.out.println("INFO: tag read Successful in method use()");

        //Generate diversified authentication key from authenticationKey(master) and readable memory.

        //Get the UID
        byte[] cardUID = new byte[8];
        boolean checkCardUID = utils.readPages(0, 2, cardUID, 0);
        if (!checkCardUID) {
            infoToShow = "Could not identify the card!";
            System.err.println("ERROR: problems while reading card UID in method use().");
            return false;
        }
        System.out.println("INFO: UID read Successful in method use()");

        //TODO: Create diversified key.

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed!";
            System.err.println("ERROR: problems while authenticating card in method use().");
            return false;
        }
        System.out.println("INFO: Authentication Successful in method use()");

        //TODO: handle the ride counter.

        //TODO: recalculate hash if necessary.

        //TODO: handle related pages in the comment in issue() method.

        //TODO: clear tag and reset AUTH bits and key? when ticket is no longer valid.

        /*
         Example of reading:
         byte[] message = new byte[4];
         res = utils.readPages(6, 1, message, 0);

         // Set information to show for the user
         if (res) {
             infoToShow = "Read: " + new String(message);
         } else {
             infoToShow = "Failed to read";
         }
        */

        return true;
    }

    /**
     * Utility Functions
     */

    private String createDiversifiedKey(String masterSecret, String UID) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-1");
            byte[] bytes = (masterSecret + "||" + UID).getBytes();
            digest.update(bytes, 0, bytes.length);
            bytes = digest.digest();
            bytes = Arrays.copyOfRange(bytes, 0, 16);
            // Create Hex String
            return convertByteArrayToHex(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private String convertByteArrayToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte aByte : bytes) hexString.append(Integer.toHexString(0xFF & aByte));
        return hexString.toString();
    }

    private byte[] intToByteArray(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    private int byteArrayToInt(byte[] value) {
        return ByteBuffer.wrap(value).getInt();
    }

    // TODO validate methods, timestamp is 19 bytes
    private String getCurrentTimeStamp() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss");
        return dateFormat.format(new Date());
    }

    private Date parseDateFromByteArray(byte[] date) {
        String s = new String((byte[]) date);
        try {
            return new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss").parse(s);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return null;
    }
}