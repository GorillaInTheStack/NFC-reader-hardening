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
    private final int remainingUses = 10; //default.
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
          Page 7: max number of uses => int uses.
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
            Utilities.log("INFO: Card UID in issue()" + convertByteArrayToHex(cardUID), false);

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
            Utilities.log("INFO: HMAC written successfully in method issue()! HMAC: "+ convertByteArrayToHex(mac), false);

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
        /*
          How the card memory is expected to be after issuing the card:

          Page 0: UID.
          Page 1: UID.
          Page 2: first byte contains UID check byte, last 2 bytes are Lock bits.
          Page 3: non-reset-able OTP.

          .... First Application Page ....
          Page 4: program tag => applicationTag.
          Page 5-6: empty in case we want to add our own ID.
          Page 7: max number of uses => int maxUsages.
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

        boolean res;

        // Check tag, if not there, return immediately.
        byte[] cardApplicationTag = new byte[4];
        boolean readSuccessful = utils.readPages(4, 1, cardApplicationTag, 0);
        if (!readSuccessful || !applicationTag.equals(new String(cardApplicationTag))) {
            infoToShow = "Ticket was not issued correctly!";
            Utilities.log("ERROR: problems while reading tag in method use().", true);
            return false;

        }
        Utilities.log("INFO: tag read Successful in method use()", false);

        // Get the UID
        byte[] cardUIDFull = new byte[8];
        boolean checkCardUID = utils.readPages(0, 2, cardUIDFull, 0);
        if (!checkCardUID) {
            infoToShow = "Unable to read UID!";
            Utilities.log("ERROR: problems while reading UID in use().", true);
            return false;
        }
        byte[] cardUID = new byte[7];
        // The UID is a 7 byte serial number located in first 3 bytes of page 0 and all of page 1
        System.arraycopy(Arrays.copyOfRange(cardUIDFull, 0, 3), 0, cardUID, 0, 3);
        System.arraycopy(Arrays.copyOfRange(cardUIDFull, 4, 8), 0, cardUID, 3, 4);
        Utilities.log("INFO: read Card UID in use() UID: " + convertByteArrayToHex(cardUID), false);

        // Create diversified keys.
        String diversifiedAuthKey = createDiversifiedKey(new String(authenticationKey), convertByteArrayToHex(cardUID));
        String diversifiedMacKey = createDiversifiedKey(new String(hmacKey), convertByteArrayToHex(cardUID));

        if (diversifiedAuthKey == null || diversifiedMacKey == null) {
            infoToShow = "Error generating keys!";
            Utilities.log("ERROR: problems while generating keys in use().", true);
            return false;
        }
        Utilities.log("INFO: Keys generated successfully in method use()!", false);

        // Authenticate
        res = utils.authenticate(diversifiedAuthKey.getBytes());
        if (!res) {
            infoToShow = "Authentication failed!";
            Utilities.log("ERROR: problems while authenticating card in method use().", true);
            return false;
        }
        Utilities.log("INFO: Authentication Successful in method use()", false);

        // Get maximum number of usages.
        byte[] rawMaxNumUsages = new byte[4];
        boolean checkMaxUsages = utils.readPages(7, 1, rawMaxNumUsages, 0);
        if (!checkMaxUsages) {
            infoToShow = "Unable to get Max number of usages!";
            Utilities.log("ERROR: problems while reading Max usages in use().", true);
            return false;
        }
        int maxUsages = byteArrayToInt(rawMaxNumUsages);
        Utilities.log("INFO: Max number of usages read successfully in use() maxUsages: "+maxUsages, false);

        // Get DaysValid from page 8.
        byte[] rawDaysValid = new byte[4];
        boolean checkDaysValid = utils.readPages(8, 1, rawDaysValid, 0);
        if (!checkDaysValid) {
            infoToShow = "Unable to get DaysValid in use()!";
            Utilities.log("ERROR: problems while reading DaysValid in use().", true);
            return false;
        }
        int daysValid = byteArrayToInt(rawDaysValid);
        Utilities.log("INFO: DaysValid read successfully in use() DaysValid: "+daysValid, false);

        // Set issue date if validating for the first time or get issue date if not.
        byte[] rawIssueDate = new byte[20];
        boolean checkIssueDate = utils.readPages(9, 5, rawIssueDate, 0);
        Date issueDate;
        if (!checkIssueDate) {
            infoToShow = "Unable to get the issue date in use()!";
            Utilities.log("ERROR: problems while reading issueDate in use().", true);
            return false;
        }else {
            int issueDateExistence = byteArrayToInt(rawIssueDate);

            if (issueDateExistence == 0) {
                //Issue date does not exist
                String currentDate = getCurrentTimeStamp();
                //System.out.println("Number of bytes in currentDate: "+currentDate.getBytes().length);
                byte[] currentDateBytes = new byte[20];
                System.arraycopy(currentDate.getBytes(), 0, currentDateBytes, 0, 19);

                //write currentDate to pages 9-13.
                //CRITICAL
                boolean writeIssueDate = utils.writePages(currentDateBytes, 0, 9, 5);
                //CRITICAL

                if (!writeIssueDate) {
                    infoToShow = "Unable to write the issue date in use()!";
                    Utilities.log("ERROR: problems while writing issueDate as currentDate in use(). currentDate: " + currentDate, true);
                    return false;
                }
                issueDate = parseDateFromByteArray(currentDateBytes);
                Utilities.log("INFO: Issue date was written successfully in use() issueDate: " + issueDate, false);

            } else {

                issueDate = parseDateFromByteArray(rawIssueDate);
                Utilities.log("INFO: Issue date read successfully in use() issueDate: " + issueDate, false);

            }
        }

        // Calculate expiry date from issue date and daysValid


        // Get mac from pages 14-18.
        byte[] rawMac = new byte[20];
        boolean checkMac = utils.readPages(14, 5, rawMac, 0);
        if (!checkMac) {
            infoToShow = "Unable to get HMAC in use()!";
            Utilities.log("ERROR: problems while reading HMAC in use().", true);
            return false;
        }
        String cardMac = convertByteArrayToHex(rawMac);
        Utilities.log("INFO: HMAC read successfully in use() HMAC: "+cardMac, false);

        // Generate HMAC which initially is HMAC("maxUsages||daysValid")
        macAlgorithm.setKey(diversifiedMacKey.getBytes());
        byte[] macGeneratedRaw = macAlgorithm.generateMac((maxUsages + "||" + daysValid).getBytes());
        String macGenerated = convertByteArrayToHex(macGeneratedRaw);

        // Compare generated mac with mac found in card.
        if(!cardMac.equals(macGenerated)){
            infoToShow = "Unable to verify HMAC in use()!";
            Utilities.log("ERROR: problems while verifying HMAC in use().", true);
            Utilities.log("ERROR: HMAC found in card: " + cardMac, true);
            Utilities.log("ERROR: HMAC generated in use(): " + macGenerated, true);
            return false;
        }
        Utilities.log("INFO: HMAC verified successfully in use()", false);
        Utilities.log("INFO: HMAC found in card: " + cardMac, false);
        Utilities.log("INFO: HMAC generated in use(): " + macGenerated, false);


        // Critical
        // TODO: recalculate hash if necessary.

        // TODO: handle related pages in the comment in issue() method.

        // TODO: clear tag and reset AUTH bits and key? when ticket is no longer valid.

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