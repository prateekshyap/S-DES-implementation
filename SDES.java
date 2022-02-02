import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

class SDES
{
    public static int[] p4 = {1,3,2,0};
    public static int[] p8 = {5,2,6,3,7,4,9,8};
    public static int[] ip = {1,5,2,0,3,7,4,6};
    public static int[] inverseIp = {3,0,2,4,6,1,7,5};
    public static int[] ep = {3,0,1,2,1,2,3,0};
    public static int[][] S0 = {{1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2}};
    public static int[][] S1 = {{0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3}};
    public static int keyLength = 10, textLength = 8;
    public static void main(String[] args)throws IOException
    {
        int i = 0;
        char temp = '\0';
        char[] plainText = null, cipherText = null, key = null, key1 = null, key2 = null;

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        
        System.out.println("Enter the plaintext-");
        plainText = reader.readLine().toCharArray();
        System.out.println("Enter the key-");
        key = reader.readLine().toCharArray();
        key1 = new char[textLength];
        key2 = new char[textLength];

        //left shift both the halves
        key = leftShift(key,keyLength);

        //produce key1
        for (i = 0; i < textLength; ++i)
            key1[i] = key[p8[i]];

        //left shift again twice
        key = leftShift(key,keyLength);
        key = leftShift(key,keyLength);

        //produce key2
        for (i = 0; i < textLength; ++i)
            key2[i] = key[p8[i]];

        System.out.println();

        cipherText = encryptAndDecrypt(plainText,key1,key2); //encryption

        //print the cipher text
        System.out.println("Cipher Text-");
        for (i = 0; i < textLength; ++i)
            System.out.print(cipherText[i]);
        System.out.println();


        plainText = encryptAndDecrypt(cipherText,key2,key1); //decryption is same as encryption only the keys will be reversed

        //print the decrypted plain text
        System.out.println("Plain Text-");
        for (i = 0; i < textLength; ++i)
            System.out.print(plainText[i]);
        System.out.println();
    }

    public static char[] leftShift(char[] key, int keyLength)
    {
        int i = 0, j = 0;
        char temp = key[0];
        for (i = 0; i < keyLength/2-1; ++i)
            key[i] = key[i+1];
        key[keyLength/2-1] = temp;
        temp = key[keyLength/2];
        for (i = keyLength/2; i < keyLength-1; ++i)
            key[i] = key[i+1];
        key[keyLength-1] = temp;
        return key;
    }

    public static char[] encryptAndDecrypt(char[] plainText, char[] key1, char[] key2)
    {
        int i = 0;
        char[] cipherText = null, permutation = null, L = null, R = null, F = null;
        char temp = '\0';
        String subText = "";

        permutation = new char[textLength];
        L = new char[textLength/2];
        R = new char[textLength];
        F = new char[textLength/2];

        //apply initital permutation on plain text
        for (i = 0; i < textLength; ++i)
            permutation[i] = plainText[ip[i]];
        plainText = permutation;

        //copy left half
        for (i = 0; i < textLength/2; ++i)
            L[i] = plainText[i];

        //apply ep on R
        for (i = 0; i < textLength; ++i)
            R[i] = plainText[ep[i]+(textLength/2)];

        //xor R with Key1
        R = xor(R,key1);

        //sbox performance
        subText = passToSBox(R,0);
        F[0] = subText.charAt(0);
        F[1] = subText.charAt(1);
        subText = passToSBox(R,1);
        F[2] = subText.charAt(0);
        F[3] = subText.charAt(1);

        //copy right half
        R = new char[textLength/2];
        for (i = 0; i < textLength/2; ++i)
            R[i] = plainText[i+(textLength/2)];

        //apply p4 to F
        permutation = new char[textLength/2];
        for (i = 0; i < textLength/2; ++i)
            permutation[i] = F[p4[i]];
        F = permutation;

        //xor L with F
        L = xor(L,F);

        //swap L and R
        permutation = L;
        L = R;
        R = permutation;

        //apply ep on R
        permutation = new char[textLength];
        for (i = 0; i < textLength; ++i)
            permutation[i] = R[ep[i]];

        //xor R with k2
        permutation = xor(permutation,key2);

        //sbox performance
        subText = passToSBox(permutation,0);
        F[0] = subText.charAt(0);
        F[1] = subText.charAt(1);
        subText = passToSBox(permutation,1);
        F[2] = subText.charAt(0);
        F[3] = subText.charAt(1);

        //apply p4 on F
        permutation = new char[textLength/2];
        for (i = 0; i < textLength/2; ++i)
            permutation[i] = F[p4[i]];
        F = permutation;

        //xor L with F
        L = xor(L,F);

        //apply inverse initial permutation on the combination of L and R to get the cipher text
        cipherText = new char[textLength];
        permutation = new char[textLength];
        for (i = 0; i < textLength/2; ++i)
            permutation[i] = L[i];
        for (i = 0; i < textLength/2; ++i)
            permutation[i+(textLength/2)] = R[i];
        for (i = 0; i < textLength; ++i)
            cipherText[i] = permutation[inverseIp[i]];

        return cipherText;
    }

    public static String passToSBox(char[] text, int boxNo)
    {
        String rowStr = "", colStr = "", resultStr = "";
        int row = 0, col = 0;
        if (boxNo == 0) //for S0
        {
            rowStr += text[0]; rowStr += text[3]; //1st and 4th bit for row
            colStr += text[1]; colStr += text[2]; //2nd and 3rd bit for column
            row = getDecimalValue(rowStr);
            col = getDecimalValue(colStr);
            return getBinaryValue(S0[row][col]);
        }
        else if (boxNo == 1) //for S1
        {
            rowStr += text[4]; rowStr += text[7]; //1st and 4th bit for row
            colStr += text[5]; colStr += text[6]; //2nd and 3rd bit for column
            row = getDecimalValue(rowStr);
            col = getDecimalValue(colStr);
            return getBinaryValue(S1[row][col]);
        }
        return "error";
    }

    public static int getDecimalValue(String text)
    {
        //convert binary strings to decimal values
        if (text.equals("00")) return 0;
        else if (text.equals("01")) return 1;
        else if (text.equals("10")) return 2;
        else if (text.equals("11")) return 3;
        return -1;
    }

    public static String getBinaryValue(int decimal)
    {
        //convert decimal values to binary strings
        if (decimal == 0) return "00";
        else if (decimal == 1) return "01";
        else if (decimal == 2) return "10";
        else if (decimal == 3) return "11";
        return "error";
    }

    public static char[] xor(char[] text1, char[] text2)
    {
        //perform xor for two given texts
        char[] result = new char[text1.length];
        for (int i = 0; i < text1.length; ++i)
        {
            if (text1[i] == '0' && text2[i] == '0') result[i] = '0';
            else if (text1[i] == '0' && text2[i] == '1') result[i] = '1';
            else if (text1[i] == '1' && text2[i] == '0') result[i] = '1';
            else if (text1[i] == '1' && text2[i] == '1') result[i] = '0';
        }
        return result;
    }
}