package pt.sirs.secureaccess.securedocument;

public class Help {
    public static void main(String[] args) {

        if (args.length != 0) {
            System.err.println("Usage: help");
            return;
        }

        String msg = "NAME\n" +
                "\tsecureaccess - secure document tool for the SecureAccess application\\n" +
                "SYNOPSYS\n" +
                "\ttsecureaccess [command] [arguments]*\n" +
                "DESCRIPTION\n" +
                "\ttsecureaccess is a library that provides cryptographic security.\n" +
                "\nCOMMANDS\n" +
                "\thelp\n" +
                "\t\tShow help page.\n" +
                "\tprotect <input_file> <output_file> <client> <id>\n" +
                "\t\tAdd security to a document. Returns the secured document.\n" +
                "\tcheck <input_file> <client>\n" +
                "\t\tVerify security of a document. Returns the result as a message.\n" +
                "\tprotect <input_file> <client>\n" +
                "\t\tRemove security from a document. Returns the unsecured document.";

        System.out.println(msg);
    }
}
