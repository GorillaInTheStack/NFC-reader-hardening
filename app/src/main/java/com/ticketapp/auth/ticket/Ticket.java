package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;
import java.util.Date;

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
          Page 2: Lock bits.
          Page 3: non-reset-able OTP.

          .... First Application Page ....
          Page 4: program tag => applicationTag.

          Page 39:
          .... Last Application Page ....

          Page 41: 16-bit counter.
          Page 42: Auth params.
          Page 43: Auth params.
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
            // erase card content
            boolean cardErased = utils.eraseMemory();
            if (!cardErased) {
                infoToShow = "Cannot erase card!";
                return false;
            }
            boolean tagWritten = utils.writePages(applicationTag.getBytes(), 0, 4, 1);
            if (tagWritten) {
                infoToShow = "Tag is written!";
                return false;
            }

            // Authenticate
//            boolean res;
//            res = utils.authenticate(authenticationKey);
//            if (!res) {
//                System.out.println("not auth");
//                Utilities.log("Authentication failed in issue()", true);
//                infoToShow = "Authentication failed";
//                return false;
//            }
        }


//
//        // Example of writing:
//        byte[] message = "info".getBytes();
//        res = utils.writePages(message, 0, 6, 1);
//
//        // Set information to show for the user
//        if (res) {
//            infoToShow = "Wrote: " + new String(message);
//        } else {
//            infoToShow = "Failed to write";
//        }
//
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
        if(!checkCardUID){
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
}