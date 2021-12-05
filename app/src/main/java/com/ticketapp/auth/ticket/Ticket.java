package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

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

    private Boolean isValid = true; //should be changed accordingly. Used elsewhere.
    private int remainingUses = 10; //default.
    private int expiryTime;
    //(int) ((new Date()).getTime() / 1000 / 60) + 1440; //default, 24h in minutes.

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
          Page 7: max number of uses => int maxUsages.
          Page 8: date after which the ticket can't be used,  season expiry date in minutes.
          Page 9: date of the first use in minutes
          Page 10: 1 day, ticket validity after first use
          Page 14-18: HMAC
          Page 19: empty
          Page 20: Temporarily used as the counter for usedRides.
          Page 21: counter initial value.

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
        if (checkApplicationTag && applicationTag.equals(new String(cardApplicationTag))) {
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
                if (!res)
                    infoToShow = "Authentication failed";
            }
            if (!res)
                Utilities.log("Authentication failed in issue()", true);
            else Utilities.log("INFO: Authentication successful in method issue()!", false);

            // Setting Auth0 to 30h to remove read and write restrictions
            byte[] page42 = new BigInteger("30000000", 16).toByteArray();
            boolean auth0Written = utils.writePages(page42, 0, 42, 1);
            if (!auth0Written) {
                infoToShow = "Failed to reset Auth0!";
                Utilities.log("ERROR: problems while resetting Auth0 in issue().", true);
                return false;
            }
            Utilities.log("INFO: Auth0 reset successfully in method issue()!", false);

            // Set counter to zero or do nothing if already used before.
            boolean initCounter = utils.writePages(new byte[4], 0, 41, 1);
            if (!initCounter) {
                infoToShow = "Unable to init counter!";
                Utilities.log("ERROR: could not init counter in issue().", true);
                return false;
            }
            Utilities.log("INFO: sent zero to counter successfully.", false);

            // Get counter value and store it to page 21 after erasing.
            byte[] rawCurrentValueCounter = new byte[4];
            boolean checkCurrentValueCounter = utils.readPages(41, 1, rawCurrentValueCounter, 0);

            byte[] twoByteCounter = new byte[4];
            //System.arraycopy(rawCurrentValueCounter, 0, twoByteCounter, 0, 2);
            twoByteCounter[2] = rawCurrentValueCounter[1];
            twoByteCounter[3] = rawCurrentValueCounter[0];
            if (!checkCurrentValueCounter) {
                infoToShow = "There was a problem reading the counter of the card!";
                Utilities.log("ERROR: problems while reading current counter in issue().", true);
                return false;
            }
            int currentCounter = byteArrayToInt(twoByteCounter);
            Utilities.log("INFO: read current counter value successfully Counter: " + currentCounter +
                    " Original counter: ", false);

            // erase card content
            boolean cardErased = utils.eraseMemory();
            if (!cardErased) {
                infoToShow = "Cannot erase card!";
                Utilities.log("ERROR: problems while erasing memory in issue().", true);
                return false;
            }
            Utilities.log("INFO: Card erased successfully in method issue()!", false);

            // Putting current counter value as initial counter in page 21.
            boolean putInitialCounterValue = utils.writePages(twoByteCounter, 0, 21, 1);
            if (!putInitialCounterValue) {
                infoToShow = "Unable to write initial counter value!";
                Utilities.log("ERROR: problems while writing initial counter value in issue().", true);
                return false;
            }
            Utilities.log("INFO: initial counter value was put successfully in issue()! Counter: " + currentCounter, false);


            // write number of uses
            boolean usesWritten = utils.writePages(intToByteArray(uses), 0, 7, 1);
            if (!usesWritten) {
                infoToShow = "Unable to write number of uses!";
                Utilities.log("ERROR: problems while writing uses in issue().", true);
                return false;
            }
            Utilities.log("INFO: Number of uses written successfully in method issue()!", false);

            // write season expiry date
            int seasonExpiryDateInMinutes = getTimeAfter((int) (new Date().getTime() / 1000 / 60), daysValid);
            boolean seasonExpiryDateWritten = utils.writePages(intToByteArray(seasonExpiryDateInMinutes), 0, 8, 1);
            if (!seasonExpiryDateWritten) {
                infoToShow = "Unable to write season expiry date!";
                Utilities.log("ERROR: problems while writing season expiry date in issue().", true);
                return false;
            }
            Utilities.log("INFO: Season expiry date written successfully in issue()!", false);

            // write number of days the ticket is valid after first use
            boolean daysValidWritten = utils.writePages(intToByteArray(1), 0, 9, 1);
            if (!daysValidWritten) {
                infoToShow = "Unable to write number of days of ticket validity!";
                Utilities.log("ERROR: problems while writing days of ticket validity in issue().", true);
                return false;
            }
            Utilities.log("INFO: Number of days of ticket validity written successfully in issue()!", false);


            // Generate and write HMAC which initially is HMAC("maxUsages||daysValid||initialCounter||issueDate")
            macAlgorithm.setKey(diversifiedMacKey.getBytes());
            byte[] mac = macAlgorithm.generateMac((uses + "||" + daysValid + "||" + currentCounter + "||" + 0).getBytes());
            boolean writeHMAC = utils.writePages(mac, 0, 14, 5);
            if (!writeHMAC) {
                infoToShow = "Unable to write HMAC!";
                Utilities.log("ERROR: problems while writing HMAC in issue().", true);
                return false;
            }
            Utilities.log("INFO: HMAC written successfully in method issue()! HMAC: " + convertByteArrayToHex(mac), false);

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
            page42 = new BigInteger("2b000000", 16).toByteArray();
            auth0Written = utils.writePages(page42, 0, 42, 1);
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
            infoToShow = "Ticket issued successfully!";
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
          Page 8: season expiry date.
          Page 9: first use DATE.
          Page 10: validity DAYS after first use.
          Page 14-18: HMAC
          Page 19: empty
          Page 20: Used for nothind. (legacy).
          Page 21: counter initial value.

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
            invalidateCard("ERROR: problems while reading tag in method use(). Re-issue the ticket.", "Ticket was not issued correctly or Card has expired!");
            return false;
        }
        Utilities.log("INFO: tag read Successful in method use()", false);

        // Get the UID
        byte[] cardUIDFull = new byte[8];
        boolean checkCardUID = utils.readPages(0, 2, cardUIDFull, 0);
        if (!checkCardUID) {
            invalidateCard("ERROR: problems while reading UID in use().", "Unable to read UID!");
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
            invalidateCard("ERROR: problems while generating keys in use().", "Error generating keys!");
            return false;
        }
        Utilities.log("INFO: Keys generated successfully in method use()!", false);

        // Authenticate
        res = utils.authenticate(diversifiedAuthKey.getBytes());
        if (!res) {
            invalidateCard("ERROR: problems while authenticating card in method use().", "Authentication failed!");
            return false;
        }
        Utilities.log("INFO: Authentication Successful in method use()", false);

        // Get maximum number of usages.
        byte[] rawMaxNumUsages = new byte[4];
        boolean checkMaxUsages = utils.readPages(7, 1, rawMaxNumUsages, 0);
        if (!checkMaxUsages) {
            invalidateCard("ERROR: problems while reading Max usages in use().", "Unable to get Max number of usages!");
            return false;
        }
        int maxUsages = byteArrayToInt(rawMaxNumUsages);
        Utilities.log("INFO: Max number of usages read successfully in use() maxUsages: " + maxUsages, false);

        // Get DaysValid from page 8.
        byte[] rawSeasonExpiry = new byte[4];
        boolean checkDaysValid = utils.readPages(8, 1, rawSeasonExpiry, 0);
        if (!checkDaysValid) {
            invalidateCard("ERROR: problems while reading DaysValid in use().", "Unable to get DaysValid in use()!");
            return false;
        }
        int seasonExpiry = byteArrayToInt(rawSeasonExpiry);
        Utilities.log("INFO: DaysValid read successfully in use() DaysValid: " + seasonExpiry, false);

        // Get the number of rides taken
        byte[] rawUsedRides = new byte[4];
        boolean checkUsedRides = utils.readPages(41, 1, rawUsedRides, 0);
        // Get only first 2 bytes
        byte[] twoByteCounter = new byte[4];
        //System.arraycopy(rawUsedRides, 0, twoByteCounter,0 , 2);
        twoByteCounter[2] = rawUsedRides[1];
        twoByteCounter[3] = rawUsedRides[0];
        if (!checkUsedRides) {
            invalidateCard("ERROR: problems while reading usedRides in use().", "Unable to get usedRides in use()!");
            return false;
        }
        int usedRides = byteArrayToInt(twoByteCounter);
        Utilities.log("INFO: read current coun ter value successfully Counter: " + usedRides +
                " Original counter: ", false);

        // We will use page 21 for initial counter value.
        byte[] rawInitialCounterValue = new byte[4];
        boolean checkInitialCounterValue = utils.readPages(21, 1, rawInitialCounterValue, 0);
        if (!checkInitialCounterValue) {
            invalidateCard("ERROR: problems while reading InitialCounterValue in use().", "Unable to get InitialCounterValue in use()!");
            return false;
        }
        int initialCounterValue = byteArrayToInt(rawInitialCounterValue);
        Utilities.log("INFO: InitialCounterValue read successfully in use() InitialCounterValue: " + initialCounterValue, false);

        // Set issue date if validating for the first time or get issue date if not.
        byte[] rawValidityDate = new byte[4];
        boolean checkIssueDate = utils.readPages(9, 1, rawValidityDate, 0);
        int firstUseDate;
        if (!checkIssueDate) {
            invalidateCard("ERROR: problems while reading issueDate in use().", "Unable to get the issue date in use()!");
            return false;
        } else {
            int issueDateExistence = byteArrayToInt(rawValidityDate);

            //Get card mac for first validation.
            String cardMAC = getCardMAC(14);
            //Validate mac for the first time.
            boolean macValid;

            // TODO: replace this check by (initial counter value ==  current counter value).
            if (issueDateExistence == 0) {
                //Issue date does not exist

                if (cardMAC != null) {
                    macValid = checkMAC(diversifiedMacKey, seasonExpiry, 0, maxUsages, initialCounterValue, cardMAC);
                } else {
                    invalidateCard("ERROR: problems while getting MAC in card in use().", "Unable to get the MAC in card in use()!");
                    return false;
                }

                if (!macValid) {
                    invalidateCard("ERROR: problems while validating first MAC in card in use().", "Unable to validate the first MAC in card in use()!");
                    eraseTag();
                    return false;
                }


                Date currentDate = new Date();
//                //System.out.println("Number of bytes in currentDate: "+currentDate.getBytes().length);
//                byte[] currentDateBytes = new byte[20];
//                System.arraycopy(currentDate.getBytes(), 0, currentDateBytes, 0, 19);

                // TODO: store int in one page instead of the Date data structure.
                //CRITICAL
                boolean writeIssueDate = utils.writePages(intToByteArray((int)(currentDate.getTime()/1000/60)), 0, 9, 1);
                //CRITICAL

                if (!writeIssueDate) {
                    invalidateCard("ERROR: problems while writing issueDate as currentDate in use(). currentDate: " + currentDate, "Unable to write the issue date in use()!");
                    eraseTag();
                    return false;
                }
                try {
                    firstUseDate = (int)(currentDate.getTime()/1000/60);
                } catch (Exception e) {
                    e.printStackTrace();
                    invalidateCard("ERROR: problems while writing issueDate as currentDate in use(). Will try to delete Tag to reissue. ", "Unable to write the issue date in use()!");
                    eraseTag();
                    return false;
                }
                Utilities.log("INFO: Issue date was written successfully in use() issueDate: " + firstUseDate, false);

                // Generate and write new MAC to only one page (4bytes).
                byte[] cardMACFromCard = generateMAC(diversifiedMacKey, seasonExpiry, (int) firstUseDate, maxUsages, initialCounterValue);
                boolean checkMACWritten = utils.writePages(cardMACFromCard, 0, 14, 1);
                if (!checkMACWritten) {
                    invalidateCard("ERROR: Was not able to update HMAC in use().", "Unable to update HMAC in use()!");
                    return false;
                }
                Utilities.log("INFO: Wrote new mac to card. New MAC: " + convertByteArrayToHex(cardMACFromCard), false);

            } else {
                // Issue date already exist.

                // Check MAC

                //Get card mac for validation.
                String cardMACNew = getCardMAC(14);
                //Validate mac.

                boolean macValidNew;

                try {
                    firstUseDate = (int) parseDateFromByteArray(rawValidityDate).getTime() /1000 /60;
                } catch (Exception e) {
                    e.printStackTrace();
                    invalidateCard("ERROR: problems while writing issueDate as currentDate in use(). Will try to delete Tag to reissue. ", "Unable to write the issue date in use()!");
                    return false;
                }
                Utilities.log("INFO: Issue date read successfully in use() issueDate: " + firstUseDate, false);


                // check HMAC which initially is HMAC("maxUsages||daysValid||currentCounter||initialCounter||issueDate")
                // This is when issue date is already set.
                if (cardMACNew != null) {
                    macValidNew = checkMAC(diversifiedMacKey, seasonExpiry, (int) firstUseDate, maxUsages, initialCounterValue, cardMACNew);
                } else {
                    invalidateCard("ERROR: problems while getting MAC in card in use().", "Unable to get the MAC in card in use()!");
                    return false;
                }

                if (!macValidNew) {
                    invalidateCard("ERROR: problems while validating the MAC in card in use().", "Unable to validate the MAC in card in use()!");
                    eraseTag();
                    return false;
                }
                Utilities.log("INFO: Mac successfully validated in use() cardMac: " + cardMACNew, false);
            }
        }

        // TODO: read the value for validity check.
//        Date expiryDate = //new Date(issueDate.getTime() + (daysValid * 86400000L));
//        Utilities.log("INFO: Calculated expiry date from issue date and daysValid expiryDate: " + expiryDate, false);
//        expiryTime = (int) (expiryDate.getTime() / 1000 / 60);
        // Get maximum number of usages.
        byte[] rawValidityDays = new byte[4];
        boolean checkValidityDays = utils.readPages(10, 1, rawValidityDays, 0);
        if (!checkValidityDays) {
            invalidateCard("ERROR: problems while reading Max usages in use().", "Unable to get Max number of usages!");
            return false;
        }
        int validityDays = byteArrayToInt(rawValidityDays);
        Utilities.log("INFO: Max number of usages read successfully in use() maxUsages: " + validityDays, false);

        //Now get time from validity days.
        //TODO: use method getTimeAfter
        int validityExpiryTime = getTimeAfter(firstUseDate, validityDays);
        int currentTime = (int) (new Date().getTime() / 1000 / 60);


        if (!(usedRides - initialCounterValue < maxUsages) || currentTime > validityExpiryTime || currentTime > seasonExpiry) {
            // Card expired.
            invalidateCard("INFO: Card has expired. Check if the values above make sense. Resetting...", "Your card has expired in use()!");
            eraseTag();
            // TODO: Reset auth params?

            Utilities.log("INFO: Card has been reset.", false);
            return false;
        } else {
            // Card is still valid, increment counter.
            usedRides += 1;
            // Write 1 to counter to increment it.
            byte[] incrementOne = new BigInteger("01000000", 16).toByteArray();
            boolean checkNewUsedRides = utils.writePages(incrementOne, 0, 41, 1);
            if (!checkNewUsedRides) {
                invalidateCard("ERROR: Was not able to update usedRides in use().", "Unable increment usedRides in use()!");
                eraseTag();
                return false;
            }
            Utilities.log("INFO: writing to counter was successful!", false);

            Utilities.log("INFO: Validation of card was successful!", false);
        }

        // Check if card still valid.
        remainingUses = maxUsages - (usedRides - initialCounterValue);


        infoToShow = "Use of card was successful!";
        isValid = true;
        return true;
    }

    /**
     * Add additional rides
     */
    public void addAdditional(int additionalRides) throws GeneralSecurityException {

        // Check the application tag
        byte[] cardApplicationTag = new byte[4];
        boolean checkApplicationTag = utils.readPages(4, 1, cardApplicationTag, 0);
        if (!checkApplicationTag || !applicationTag.equals(new String(cardApplicationTag))) {
            infoToShow = "Unable to read application tag!";
            Utilities.log("ERROR: problems while reading tag in method addAdditional().", true);
            return;
        }

        byte[] cardUIDFull = new byte[8];
        boolean checkCardUID = utils.readPages(0, 2, cardUIDFull, 0);
        if (!checkCardUID) {
            infoToShow = "Unable to read UID!";
            Utilities.log("ERROR: problems while reading UID in addAdditional().", true);
            return;
        }
        byte[] cardUID = new byte[7];
        // The UID is a 7 byte serial number located in first 3 bytes of page 0 and all of page 1
        System.arraycopy(Arrays.copyOfRange(cardUIDFull, 0, 3), 0, cardUID, 0, 3);
        System.arraycopy(Arrays.copyOfRange(cardUIDFull, 4, 8), 0, cardUID, 3, 4);
        Utilities.log("INFO: Card UID in addAdditional(). Card UID: " + convertByteArrayToHex(cardUID), false);

        String diversifiedAuthKey = createDiversifiedKey(new String(authenticationKey), convertByteArrayToHex(cardUID));
        String diversifiedMacKey = createDiversifiedKey(new String(hmacKey), convertByteArrayToHex(cardUID));

        if (diversifiedAuthKey == null || diversifiedMacKey == null) {
            infoToShow = "Error generating keys!";
            Utilities.log("ERROR: problems while generating keys in addAdditional().", true);
            return;
        }
        Utilities.log("INFO: Keys generated successfully in addAdditional()!", false);

        // Authenticate
        boolean res;
        res = utils.authenticate(diversifiedAuthKey.getBytes());
        if (!res) {
            infoToShow = "Authentication failed";
            Utilities.log("Authentication failed in addAdditional()", true);
            return;
        }
        Utilities.log("INFO: Authentication successful in addAdditional()!", false);

        // Get maximum number of usages.
        byte[] rawMaxNumUsages = new byte[4];
        boolean checkMaxUsages = utils.readPages(7, 1, rawMaxNumUsages, 0);
        if (!checkMaxUsages) {
            infoToShow = "Unable to get Max number of usages!";
            Utilities.log("ERROR: problems while reading Max usages in addAdditional().", true);
            return;
        }
        int maxUsages = byteArrayToInt(rawMaxNumUsages);
        Utilities.log("INFO: Max number of usages read successfully in addAdditional(). maxUsages: " + maxUsages, false);

        // Get DaysValid from page 8.
        byte[] rawDaysValid = new byte[4];
        boolean checkDaysValid = utils.readPages(8, 1, rawDaysValid, 0);
        if (!checkDaysValid) {
            infoToShow = "Unable to get DaysValid in use()!";
            Utilities.log("ERROR: problems while reading DaysValid in addAdditional().", true);
            return;
        }
        int daysValid = byteArrayToInt(rawDaysValid);
        Utilities.log("INFO: DaysValid read successfully in addAdditional() DaysValid: " + daysValid, false);

        // Get issueDate
        byte[] rawIssueDate = new byte[20];
        boolean checkIssueDate = utils.readPages(9, 5, rawIssueDate, 0);
        if (!checkIssueDate) {
            infoToShow = "Unable to get the issue date in addAdditional()!";
            Utilities.log("ERROR: problems while reading issueDate in addAdditional().", true);
            return;
        }

        int issueDateExistence = byteArrayToInt(rawIssueDate);
        int issueDate;
        if (issueDateExistence == 0)
            issueDate = 0;
        else {
            try {
                issueDate = (int) parseDateFromByteArray(rawIssueDate).getTime();
            } catch (Exception e) {
                e.printStackTrace();
                infoToShow = "Unable to parse the issue date in addAdditional()!";
                Utilities.log("ERROR: problems while parsing issueDate in addAdditional().", true);
                return;
            }
        }
        Utilities.log("INFO: issueDate read successfully in addAdditional(). issueDate: " + issueDate, false);

        // read card MAC
        byte[] rawMac = new byte[4];
        boolean checkMac = utils.readPages(14, 1, rawMac, 0);
        if (!checkMac) {
            infoToShow = "Unable to get HMAC in use()!";
            Utilities.log("ERROR: problems while reading HMAC in addAdditional().", true);
            return;
        }
        String cardMac = convertByteArrayToHex(rawMac);
        Utilities.log("INFO: HMAC read successfully in addAdditional() HMAC: " + cardMac, false);

        // Read initial counter value.
        byte[] rawInitialCounterValue = new byte[4];
        boolean checkInitialCounterValue = utils.readPages(21, 1, rawInitialCounterValue, 0);
        if (!checkInitialCounterValue) {
            infoToShow = "Unable to get InitialCounterValue!";
            Utilities.log("ERROR: problems while reading InitialCounterValue in addAdditional().", true);
            return;
        }
        int initialCounterValue = byteArrayToInt(rawInitialCounterValue);
        Utilities.log("INFO: InitialCounterValue read successfully in addAdditional() InitialCounterValue: " + initialCounterValue, false);


        boolean compareMac = checkMAC(diversifiedMacKey, daysValid, issueDate, maxUsages, initialCounterValue, cardMac);
        if (!compareMac) {
            infoToShow = "MACs don't match!";
            Utilities.log("ERROR: problems while comparing HMAC in addAdditional().", true);
            eraseTag();
            return;
        }

        // write new number of uses
        boolean usesWritten = utils.writePages(intToByteArray(maxUsages + additionalRides), 0, 7, 1);
        if (!usesWritten) {
            infoToShow = "Unable to write  new number of uses!";
            Utilities.log("ERROR: problems while writing new number of uses in addAdditional().", true);
            eraseTag();
            return;
        }
        Utilities.log("INFO: Number of uses written successfully in method addAdditional()! Uses: " + (maxUsages + additionalRides), false);


        // Generate and write new MAC to only one page (4bytes).
        byte[] cardMACFromCard = generateMAC(diversifiedMacKey, daysValid, issueDate, maxUsages + additionalRides, initialCounterValue);
        boolean checkMACWritten = utils.writePages(cardMACFromCard, 0, 14, 1);
        if (!checkMACWritten) {
            infoToShow = "Unable to update HMAC in use()!";
            Utilities.log("ERROR: Was not able to update HMAC in use().", true);
            eraseTag();
            return;
        }
        infoToShow = "Added 5 rides successfully!";
        Utilities.log("INFO: Wrote new mac to card. New MAC: " + convertByteArrayToHex(cardMACFromCard), false);

    }


    /**
     * Utility Functions
     */

    private int getTimeAfter(int date, int days) {
        return date + days * 24 * 60;
    }

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

    private void invalidateCard(String ErrorMessage, String messageToShow) {
        infoToShow = messageToShow;
        Utilities.log(ErrorMessage, true);
        isValid = false;
    }

    private void eraseTag() {
        // Erase Tag
        boolean eraseTag = utils.writePages(intToByteArray(0), 0, 4, 1);
        if (!eraseTag) {
            Utilities.log("ERROR: Could not invalidate card correctly, Tag was not erased.", true);
        }
    }

    // TODO validate methods, timestamp is 19 bytes
    private String getCurrentTimeStamp() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss", Locale.getDefault());
        return dateFormat.format(new Date());
    }

    private Date parseDateFromByteArray(byte[] date) throws Exception {
        String s = new String(date);
        try {
            return new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss", Locale.getDefault()).parse(s);
        } catch (ParseException e) {
            throw new Exception(e);
        }
    }

    private boolean checkMAC(String diversifiedMacKey, int daysValid, int issueDate, int maxUsages, int initialCounter, String cardMAC) throws GeneralSecurityException {
        String macGenerated = convertByteArrayToHex(generateMAC(diversifiedMacKey, daysValid, issueDate, maxUsages, initialCounter));
        Utilities.log("INFO: checkMAC is comparing cardMAC: " + cardMAC + " With generatedMac: " + macGenerated, false);
        return cardMAC.equals(macGenerated);
    }

    private byte[] generateMAC(String diversifiedMacKey, int daysValid, int issueDate, int maxUsages, int initialCounter) throws GeneralSecurityException {
        // Generate HMAC which initially is HMAC("maxUsages||daysValid||initialCounter||issueDate")
        macAlgorithm.setKey(diversifiedMacKey.getBytes());
        byte[] mac = macAlgorithm.generateMac((maxUsages + "||" + daysValid + "||" + initialCounter + "||" + issueDate).getBytes());
        // Take only first 4 bytes.
        byte[] macGeneratedRaw = new byte[4];
        System.arraycopy(mac, 0, macGeneratedRaw, 0, 4);

        return macGeneratedRaw;
    }

    private String getCardMAC(int startPage) {
        // Get mac from pages 14-18.
        // Get only first 4 bytes.
        byte[] rawMac = new byte[4];
        boolean checkMac = utils.readPages(startPage, 1, rawMac, 0);
        if (!checkMac) {
            invalidateCard("ERROR: problems while reading HMAC in use().", "Unable to get HMAC in use()!");
            return null;
        }
        String cardMac = convertByteArrayToHex(rawMac);
        Utilities.log("INFO: HMAC read successfully in use() HMAC: " + cardMac, false);
        return cardMac;

    }
}