import java.io.*;
import java.util.Scanner;

public class RC6 {
    private static int w = 32;
    private static int r = 20;
    private static int Pw = 0xB7E15163;
    private static int Qw = 0x9E3779b9;
    private static int[] S = new int[r * 2 + 4];

    private static int rotateL(int n, int x){
        return ((n << x) | (n >>> (w - x)));
    }

    private static int rotateR(int n, int x){
        return ((n >>> x) | (n << (w - x)));
    }

    private static byte[] allignHex(int regA,int regB, int regC, int regD){
        int[] data = new int[4];
        byte[] text = new byte[w / 2];

        data[0] = regA;
        data[1] = regB;
        data[2] = regC;
        data[3] = regD;

        for(int i = 0;i < text.length;i++){
            text[i] = (byte)((data[i/4] >>> (i%4)*8) & 0xff);
        }
        return text;
    }

    private static void keyGen(byte[] key){
        int bytes = w / 8;
        int c = key.length / bytes;
        int[] L = new int[c];
        int index = 0;

        for(int i = 0; i < c; i++){
            L[i] = ((key[index++]) & 0xff | (key[index++] & 0xff) << 8 | (key[index++] & 0xff) << 16 | (key[index++] & 0xff) << 24);
        }
        S[0] = Pw;

        for(int i = 1; i <= 2*r+3; i++){
            S[i] = S[i-1] + Qw;
        }

        int A = 0, B = 0, i = 0,j =0;
        int v = 3 * Math.max(c, 2*r+4);

        for(int k = 1;k <= v; k++){
            A = S[i] = rotateL(S[i] + A + B, 3);
            B = L[j] = rotateL(L[j] + A + B, A+B);
            i = (i + 1) % (2 * r + 4);
            j = (j + 1) % c;
        }
    }

    private static byte[] encrypt(byte[] plainText, byte[] userKey){
        int regA, regB, regC, regD;
        int index = 0, temp1, temp2, swap;

        regA = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8| (plainText[index++] & 0xff) << 16| (plainText[index++] & 0xff)<<24);
        regB = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8| (plainText[index++] & 0xff) << 16| (plainText[index++] & 0xff)<<24);
        regC = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8| (plainText[index++] & 0xff) << 16| (plainText[index++] & 0xff)<<24);
        regD = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8| (plainText[index++] & 0xff) << 16| (plainText[index++] & 0xff)<<24);

        keyGen(userKey);

        regB = regB + S[0];
        regD = regD + S[1];

        for(int i = 1; i <= r ; i++){
            temp1 = rotateL(regB * (regB * 2 + 1), (int)(Math.log(w)/Math.log(2)));
            temp2 = rotateL(regD * (regD * 2 + 1), (int)(Math.log(w)/Math.log(2)));
            regA = (rotateL(regA ^ temp1, temp2)) + S[i * 2];
            regC = (rotateL(regC ^ temp2, temp1)) + S[i * 2 + 1];

            swap = regA;
            regA = regB;
            regB = regC;
            regC = regD;
            regD = swap;
        }

        regA = regA + S[r * 2 + 2];
        regC = regC + S[r * 2 + 3];

        return allignHex(regA, regB, regC, regD);
    }

    public static byte[] decrypt(byte[] cipherText, byte[]userKey){
        int regA, regB, regC, regD;
        int index = 0, temp1, temp2, swap;

        regA = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8| (cipherText[index++] & 0xff) << 16| (cipherText[index++] & 0xff)<<24);
        regB = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8| (cipherText[index++] & 0xff) << 16| (cipherText[index++] & 0xff)<<24);
        regC = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8| (cipherText[index++] & 0xff) << 16| (cipherText[index++] & 0xff)<<24);
        regD = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8| (cipherText[index++] & 0xff) << 16| (cipherText[index++] & 0xff)<<24);

        keyGen(userKey);

        regC = regC - S[r * 2 + 3];
        regA = regA - S[r * 2 + 2];

        for(int i = r; i >= 1 ; i--){
            swap = regD;
            regD = regC;
            regC = regB;
            regB = regA;
            regA = swap;

            temp2 = rotateL(regD * (regD * 2 + 1), (int)(Math.log(w)/Math.log(2)));
            temp1 = rotateL(regB * (regB * 2 + 1), (int)(Math.log(w)/Math.log(2)));
            regC =  rotateR(regC - S[i * 2 + 1], temp1) ^ temp2;
            regA =  rotateR(regA -  + S[i * 2], temp2) ^ temp1;
        }

        regD = regD - S[1];
        regB = regB - S[0];

        return allignHex(regA, regB, regC, regD);
    }


    private static void writeFile(String fileName,String output){

        try {

            PrintWriter printWriter = new PrintWriter(fileName, "UTF-8");
            printWriter.write(output);
            printWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        try{
            int globalChoice = 0;
            String[] text;
            byte[] plainText, userKey, cipherText;
            Scanner scanner = new Scanner(System.in);
            do{
                BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
                System.out.println("Press [1] - for encrypt message\n" +
                        "Press [2] - for decrypt message");
                int userChoice = scanner.nextInt();

                switch (userChoice) {
                    case 1:
                        FileOutputStream fos = new FileOutputStream("C:\\Users\\User\\Desktop\\encryptResult.txt");
                        FileInputStream fis = new FileInputStream("C:\\Users\\User\\Desktop\\input.txt");

                        InputStreamReader isr = new InputStreamReader(fis, "UTF-8");

                        BufferedReader inputFile = new BufferedReader(isr);
                        String inputText = inputFile.readLine();

                        byte[] tmpMessage = (inputText.getBytes("866"));

                        System.out.println("Input key for encrypt: ");
                        String key = input.readLine();

                        byte[] tmpKey = (key.getBytes("866"));

                        int size = tmpMessage.length;
                        int iterSize = 0;
                        int totalArraySize = 0;

                        if(tmpMessage.length % 16 == 0){
                            totalArraySize = tmpMessage.length;
                        }
                        else {
                            totalArraySize = (tmpMessage.length/16 + 1) * 16;
                        }
                        iterSize = totalArraySize/16;
                        String resultStr = "";

                        byte[] testUserKey = new byte[16];
                        for (int i = 0; i < tmpKey.length; ++i) {
                            testUserKey[i] = tmpKey[i];
                        }
                        for (int i = tmpKey.length; i < 16; ++i) {
                            testUserKey[i] = 0;
                        }

                        byte[] toFileArray = new byte[totalArraySize];


                        for(int j = 0; j < iterSize; ++j) {
                            byte[] currentByte;

                            int messageLength = 0;
                            byte[] testPlainText = new byte[16];

                            for (int i = 0; i < 16; ++i) {
                                if(i+(16*j) >= size)
                                    break;
                                else
                                    ++messageLength;
                                testPlainText[i] = tmpMessage[i + (16*j)];
                            }
                            currentByte = encrypt(testPlainText, testUserKey);
                            for(int i = 0; i < 16; ++i){
                                toFileArray[i+(16*j)] = currentByte[i];
                            }
                        }

                        fos.write(toFileArray);
                        break;

                    case 2:
                        FileInputStream inputStream = new FileInputStream("C:\\Users\\User\\Desktop\\encryptResult.txt");
                        cipherText = inputStream.readAllBytes();

                        System.out.println("Input key for decrypt: ");
                        String keyDec = input.readLine();
                        byte[] tmpKeyDec = (keyDec.getBytes("866"));


                        byte[] testUserKeyDec = new byte[16];
                        for(int i = 0; i < tmpKeyDec.length; ++i){
                            testUserKeyDec[i] = tmpKeyDec[i];
                        }
                        for(int i = tmpKeyDec.length; i < 16; ++i)
                        {
                            testUserKeyDec[i] = 0;
                        }
                        String resultStrDec = "";
                        int cipherTextSize = cipherText.length;
                        int iterSizeDec = 0;
                        if(cipherText.length % 16 == 0){
                            iterSizeDec = cipherText.length/16;
                        }
                        else{
                            iterSizeDec = cipherText.length/16 + 1;
                        }

                        for(int i = 0; i <  iterSizeDec; ++i) {

                            byte[] forWriteToFileArray;
                            byte[] currentCipherText = new byte[16];
                            for (int j = 0; j < 16; ++j) {
                                if (j + (16 * i) >= cipherTextSize)
                                    break;
                                else
                                    currentCipherText[j] = cipherText[j + 16 * i];
                            }

                            if (cipherText.length - (16 * i) < 16) {
                                for (int j = cipherText.length - (16 * i); i < 16; ++i) {
                                    currentCipherText[i] = 0;
                                }
                            }

                            forWriteToFileArray = decrypt(currentCipherText, testUserKeyDec);
                            String s = new String(forWriteToFileArray, "866");
                            resultStrDec += s;
                        }
                        writeFile("C:\\Users\\User\\Desktop\\decrypt.txt", resultStrDec);
                        System.out.println("Decrypted message: " + resultStrDec);

                        break;

                    default:
                        break;
                }

                System.out.println("Press [1] - for repeat\n" +
                        "Press [0] - for exit");
                globalChoice = Integer.parseInt(input.readLine());

            }while (globalChoice != 0);

        }
        catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}
