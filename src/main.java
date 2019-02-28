import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/*
 * Simple program that I wrote for password cracking assignment on Information Security course.
 * First we needed to get password hashes from web server with SQL injection.
 * Then we compute hashes from common passwords with common prefixes and simply compare it to hashes received from server.
 * Uses as many threads as possible.
 */

public class main {

    private int            maxCores;
    private String[]       hashes;
    private String[]       salts;
    private String[]       passwords;
    private String[]       passPrefixes;
    private final String   prefix;

    private ExecutorService es;

    public main() {
        // Prefix for all passwords
        prefix = "potplantspw";

        System.out.println("STARTED!");
        initValues();
        System.out.println("VALUES READY!");

        // Set DateTimeFormatter and get starting time.
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
        LocalDateTime now;
        now = LocalDateTime.now();
        System.out.println("Start time: " + dtf.format(now));

        // Get max amount of threads and initialize fixed threadpool
        maxCores = Runtime.getRuntime().availableProcessors();
        es = Executors.newFixedThreadPool(maxCores);

        // Loop maxCores, spawn new workingThread, pass thread index to it as parameter and execute it.
        for(int r = 0; r < maxCores; r++){
            WorkerThread wt = new WorkerThread(r);
            es.execute(wt);
        }

        // Shutdown executor and wait for it to terminate.
        es.shutdown();
        while (!es.isTerminated()) {
        }

        // Get finish time
        now = LocalDateTime.now();
        System.out.println("Finished all threads! End time: " + dtf.format(now));

        System.out.println("FINISHED!");

    }

    // Function to read default/common passwords from file. Returns array of strings
    private String[] importPasswordsFromFile(String fileName){
        List<String> tempList = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(new FileInputStream(fileName)));
            String line;
            while((line = br.readLine()) != null){
                if(line.length() > 2 && line.length() < 13) {
                    new StringBuilder(line).reverse().toString();
                    tempList.add(line);
                    //System.out.println(line);
                }
            }
            br.close();

        } catch(Exception e) {
            e.printStackTrace();
        }
        return stringListToArray(tempList);
    }

    // Convert list to array
    private String[] stringListToArray(List<String> l){
        String[] res = new String[l.size()];
        for(int i = 0; i < l.size(); i++){
            res[i] = l.get(i);
        }
        return res;
    }

    // Convert bytes to hexString
    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Helper function to build final password string
    private String getFullString(int passIdx, int saltIdx){
        String res = prefix + passwords[passIdx] + salts[saltIdx];
        return res;
    }

    // Initialize hashes, salts, passwords and passwordprefixes
    private void initValues(){
        hashes = new String[] {     "d1e71bdf3b65478a1f56b29cfe152bf1",
                                    "df2e88ae349cb1654f124480cf2ecd5a",
                                    "feeb4039c898273b0277932a085eef06",
                                    "9a1c8c7e72aa29aef04d4a1ec8b7f1ec",
                                    "79de656737ebe02406f872e0b71b5620", "6e040cba15a88d227dc6d7e882b3fbcf",
                                    "d93de3cdb9f508d630aede51e5e284ec",
                                    "b5024369f65e4bafc497574af331ce36",
                                    "a60ac66ccc799b485dc115adb804f7bb",
                                    "29a3ec29e3f69e9b7eedba9f1f68455c", "0ce3dc38cc944b5c5b4df18e38280de1",
                                    "b64fd389654413ff338909c65ff036cb",
                                    "29eb791f1c461f681bc6dfa8d42928a7", "3c4f6d2742fb28238cd338782e43f824",
                                    "ca52a1e6bbe10a3f91bd475f965508a4", "66cbb10f27e1a82b459c973943a2a6a5",
                                    "5220e49226819222fc97dd145f876170", "5fe83228d93bd54a28c57010b53ee4a8",
                                    "5ff3e0753f9e9a3a3c04e7afd38016a1"};

        salts = new String[] {      "2c5964b6d74813a8",
                                    "c76a016835ee7a06",
                                    "257b9fe576ecffef",
                                    "93d75a9f7e5f53e3",
                                    "a0dfd7e46705e847", "9b88cfab5b81d51b",
                                    "eefbf276db806f56",
                                    "4d585fd0797c9d1c",
                                    "176dfee89c91500a",
                                    "baf66c319004fc43", "eccce5cc32c605ef",
                                    "9e34fd96e212028a",
                                    "c480e7628ce81946", "9b88cfab5b81d51b",
                                    "af9bdd6667e00707", "8a8e0a1c363e2cc5",
                                    "44598d822b0248a4", "1b541d87d11fd8cf",
                                    "0435d62882ffed07"};

        passwords = importPasswordsFromFile("C://users/otto/desktop/infosec/MainEnglishDictionary_ProbWL.txt");

        passPrefixes = new String[117];   // Add numbers from 0 to 100 to prefixes
        for(int i = 0; i < 101; i++){ // 101
            passPrefixes[i] = Integer.toString(i);
        }
        passPrefixes[101] = "!"; passPrefixes[102] = "@"; passPrefixes[103] = "$";    // Add special characters to prefixes
        passPrefixes[104] = "%"; passPrefixes[105] = "^"; passPrefixes[106] = "&";
        passPrefixes[107] = "*"; passPrefixes[108] = "("; passPrefixes[109] = ")";
        passPrefixes[110] = "-"; passPrefixes[111] = "="; passPrefixes[112] = "_";
        passPrefixes[113] = "+"; passPrefixes[114] = "<"; passPrefixes[115] = ">";
        passPrefixes[116] = "?";

    }

    // Main function to start our program.
    public static void main(String args[]){
        new main();
    }

    /*
     * WorkerThread takes thread index as parameter in constructor.
     * Index is needed to avoid multiple threads reading and thus computing same password hashes
     */
    class WorkerThread implements Runnable {

        private final int threadIdx;

        public WorkerThread(int idx){
            threadIdx = idx;
        }

        @Override
        public void run(){
            try {
                String temp1, temp2, temp3, temp4, temp5, res1, res2, res3, res4, res5;
                byte[] encoded1, encoded2, encoded3, encoded4, encoded5;

                // SHA-256 hasher
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

                DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
                LocalDateTime now;

                // Every thread loops through all salts and designated block of passwords
                for (int x = 0; x < salts.length; x++) {
                    int blockSize = passwords.length/maxCores;
                    int startIdx = threadIdx * blockSize;
                    for (int y = startIdx; y < startIdx + blockSize; y++) {
                        if (y < passwords.length) {

                            temp1 = prefix + passwords[y] + salts[x];          // Hash only the password
                            encoded1 = messageDigest.digest(temp1.getBytes());
                            res1 = bytesToHex(encoded1).substring(0, 32);

                            if (res1.equals(hashes[x])) {
                                System.out.print("WE GOT A MATCH!!\n" + "AND THE PASSWORD IS: " + temp1 + "\n");
                            }

                            // This loop is for prefixes in front and back.
                            for(int z = 100; z < passPrefixes.length; z++) {
                                temp2 = prefix + passPrefixes[z] + passwords[y] + salts[x];     // Add password prefix to front and back
                                temp3 = prefix + passwords[y] + passPrefixes[z] + salts[x];

                                encoded2 = messageDigest.digest(temp2.getBytes());
                                encoded3 = messageDigest.digest(temp3.getBytes());

                                res2 = bytesToHex(encoded2).substring(0, 32);   // Convert bytes to hex and truncate to 32 bytes
                                res3 = bytesToHex(encoded3).substring(0, 32);

                                if (res2.equals(hashes[x])) {
                                    System.out.print("WE GOT A MATCH!!\n" + "AND THE PASSWORD IS: " + temp2 + "\n");
                                }
                                if (res3.equals(hashes[x])) {
                                    System.out.print("WE GOT A MATCH!!\n" + "AND THE PASSWORD IS: " + temp3 + "\n");
                                }
                            }

                            // Word combinations here, if not needed change w < passwords.length to w < 0 and vice versa. Very time consuming; O(n^n), n = number of passwords
                            for(int w = 0; w < 0; w++){
                                temp4 = prefix + passwords[y] + passwords[w] + salts[x];
                                temp5 = prefix + passwords[w] + passwords[y] + salts[x];

                                encoded4 = messageDigest.digest(temp4.getBytes());
                                encoded5 = messageDigest.digest(temp5.getBytes());

                                res4 = bytesToHex(encoded4).substring(0, 32);
                                res5 = bytesToHex(encoded5).substring(0, 32);

                                if (res4.equals(hashes[x])) {
                                    System.out.print("WE GOT A MATCH!!\n" + "AND THE PASSWORD IS: " + temp4 + "\n");
                                }
                                if (res5.equals(hashes[x])) {
                                    System.out.print("WE GOT A MATCH!!\n" + "AND THE PASSWORD IS: " + temp5 + "\n");
                                }
                            }
                        }
                    }

                    // Just some print outs to keep track of progress.
                    if(x == salts.length/4) {
                        now = LocalDateTime.now();
                        System.out.println("Thread number: " + threadIdx + "  1/4 done!  Time: " + dtf.format(now));
                    }
                    if(x == salts.length/2){
                        now = LocalDateTime.now();
                        System.out.println("Thread number: " + threadIdx + "  Halfway there!  Time: " + dtf.format(now));
                    }
                    if(x == (int)(salts.length * (3.0/4.0))){
                        now = LocalDateTime.now();
                        System.out.println("Thread number: " + threadIdx + "  3/4 done!  Time: " + dtf.format(now));
                    }
                    if(x == salts.length - 1){
                        now = LocalDateTime.now();
                        System.out.println("Thread number: " + threadIdx + "  Finished in time: " + dtf.format(now));
                    }
                }
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
    }
}
