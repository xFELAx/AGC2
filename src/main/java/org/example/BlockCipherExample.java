package org.example;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import org.jfree.chart.*;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;

public class BlockCipherExample {

    public static void main(String[] args) throws Exception {

        String inputFile1 = "1MB";
        String inputFile2 = "5MB";
        String inputFile3 = "10MB";

        String keyString = "mySecretKey12345"; // klucz szyfrujący
        byte[] keyData = keyString.getBytes(StandardCharsets.UTF_8);

        SecretKeySpec key = new SecretKeySpec(keyData, "AES"); // klucz AES

        int[] fileSizes = {1048576, 5242880, 10485760}; // rozmiary plików

        DefaultCategoryDataset datasetEncryption = new DefaultCategoryDataset();
        DefaultCategoryDataset datasetDecryption = new DefaultCategoryDataset();

        for (int fileSize : fileSizes) {
            byte[] data1 = generateRandomData(fileSize); // generuje losowe dane o podanym rozmiarze
            byte[] data2 = generateRandomData(fileSize);
            byte[] data3 = generateRandomData(fileSize);

            Path inputPath1 = Paths.get(inputFile1);
            Path inputPath2 = Paths.get(inputFile2);
            Path inputPath3 = Paths.get(inputFile3);

            Files.write(inputPath1, data1); // zapisuje dane do pliku
            Files.write(inputPath2, data2);
            Files.write(inputPath3, data3);

            // szyfrowanie i deszyfrowanie w trybie ECB
            List<Long> ecbEncryptionTimes = new ArrayList<>();
            List<Long> ecbDecryptionTimes = new ArrayList<>();

            long ecbEncryptionTotalTime = 0;
            long ecbDecryptionTotalTime = 0;

            for(int i=0; i<5; i++) { //powtarzamy pomiar 5 razy
                long[] ecbTimes = encryptAndDecrypt(key, inputPath1, "AES/ECB/PKCS5Padding");
                ecbEncryptionTimes.add(ecbTimes[0]);
                ecbEncryptionTotalTime += ecbTimes[0];
                ecbDecryptionTimes.add(ecbTimes[1]);
                ecbDecryptionTotalTime += ecbTimes[1];
            }
            double ecbEncryptionAverageTime = ecbEncryptionTotalTime / 5.0;
            double ecbDecryptionAverageTime = ecbDecryptionTotalTime / 5.0;
            datasetEncryption.addValue(ecbEncryptionAverageTime, "AES/ECB/PKCS5Padding", "Encryption");
            datasetDecryption.addValue(ecbDecryptionAverageTime, "AES/ECB/PKCS5Padding", "Decryption");

            // szyfrowanie i deszyfrowanie w trybie CBC
            byte[] iv = generateRandomData(16); // inicjalizacja wektora (IV) dla CBC
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            List<Long> cbcEncryptionTimes = new ArrayList<>();
            List<Long> cbcDecryptionTimes = new ArrayList<>();

            long cbcEncryptionTotalTime = 0;
            long cbcDecryptionTotalTime = 0;

            for(int i=0; i<5; i++) { //powtarzamy pomiar 5 razy
                long[] cbcTimes = encryptAndDecrypt(key, ivSpec, inputPath1, "AES/CBC/PKCS5Padding");
                cbcEncryptionTimes.add(cbcTimes[0]);
                cbcEncryptionTotalTime += cbcTimes[0];
                cbcDecryptionTimes.add(cbcTimes[1]);
                cbcDecryptionTotalTime += cbcTimes[1];

            }
            double cbcEncryptionAverageTime = cbcEncryptionTotalTime / 5.0;
            double cbcDecryptionAverageTime = cbcDecryptionTotalTime / 5.0;
            datasetEncryption.addValue(cbcEncryptionAverageTime, "AES/CBC/PKCS5Padding", "Encryption");
            datasetDecryption.addValue(cbcDecryptionAverageTime, "AES/CBC/PKCS5Padding", "Decryption");

            // szyfrowanie i deszyfrowanie w trybie OFB
            byte[] iv2 = generateRandomData(16); // inicjalizacja wektora (IV) dla OFB
            IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);

            List<Long> ofbEncryptionTimes = new ArrayList<>();
            List<Long> ofbDecryptionTimes = new ArrayList<>();

            long ofbEncryptionTotalTime = 0;
            long ofbDecryptionTotalTime = 0;

            for(int i=0; i<5; i++) { //powtarzamy pomiar 5 razy
                long[] ofbTimes = encryptAndDecrypt(key, ivSpec2, inputPath1, "AES/OFB/PKCS5Padding");
                ofbEncryptionTimes.add(ofbTimes[0]);
                ofbEncryptionTotalTime += ofbTimes[0];
                ofbDecryptionTimes.add(ofbTimes[1]);
                ofbDecryptionTotalTime += ofbTimes[1];
            }
            double ofbEncryptionAverageTime = ofbEncryptionTotalTime / 5.0;
            double ofbDecryptionAverageTime = ofbDecryptionTotalTime / 5.0;
            datasetEncryption.addValue(ofbEncryptionAverageTime, "AES/OFB/PKCS5Padding", "Encryption");
            datasetDecryption.addValue(ofbDecryptionAverageTime, "AES/OFB/PKCS5Padding", "Decryption");

            // szyfrowanie i deszyfrowanie w trybie CFB
            byte[] iv3 = generateRandomData(16); // inicjalizacja wektora (IV) dla CFB
            IvParameterSpec ivSpec3 = new IvParameterSpec(iv3);

            List<Long> cfbEncryptionTimes = new ArrayList<>();
            List<Long> cfbDecryptionTimes = new ArrayList<>();

            long cfbEncryptionTotalTime = 0;
            long cfbDecryptionTotalTime = 0;

            for(int i=0; i<5; i++) { //powtarzamy pomiar 5 razy
                long[] cfbTimes = encryptAndDecrypt(key, ivSpec3, inputPath1, "AES/CFB/PKCS5Padding");
                cfbEncryptionTimes.add(cfbTimes[0]);
                cfbEncryptionTotalTime += cfbTimes[0];
                cfbDecryptionTimes.add(cfbTimes[1]);
                cfbDecryptionTotalTime += cfbTimes[1];
            }
            double cfbEncryptionAverageTime = cfbEncryptionTotalTime / 5.0;
            double cfbDecryptionAverageTime = cfbDecryptionTotalTime / 5.0;
            datasetEncryption.addValue(cfbEncryptionAverageTime, "AES/CFB/PKCS5Padding", "Encryption");
            datasetDecryption.addValue(cfbDecryptionAverageTime, "AES/CFB/PKCS5Padding", "Decryption");

            // szyfrowanie i deszyfrowanie w trybie CTR
            byte[] nonce = generateRandomData(16); // inicjalizacja wartości nonce dla CTR
            IvParameterSpec ivSpec4 = new IvParameterSpec(nonce);

            List<Long> ctrEncryptionTimes = new ArrayList<>();
            List<Long> ctrDecryptionTimes = new ArrayList<>();

            long ctrEncryptionTotalTime = 0;
            long ctrDecryptionTotalTime = 0;

            for(int i=0; i<5; i++) { //powtarzamy pomiar 5 razy
                long[] ctrTimes = encryptAndDecrypt(key, ivSpec4, inputPath1, "AES/CTR/NoPadding");
                ctrEncryptionTimes.add(ctrTimes[0]);
                ctrEncryptionTotalTime += ctrTimes[0];
                ctrDecryptionTimes.add(ctrTimes[1]);
                ctrDecryptionTotalTime += ctrTimes[1];
            }
            double ctrEncryptionAverageTime = ctrEncryptionTotalTime / 5.0;
            double ctrDecryptionAverageTime = ctrDecryptionTotalTime / 5.0;
            datasetEncryption.addValue(ctrEncryptionAverageTime, "AES/CTR/NoPadding", "Encryption");
            datasetDecryption.addValue(ctrDecryptionAverageTime, "AES/CTR/NoPadding","Decryption");

        }

        // tworzenie wykresów
        JFreeChart encryptionChart = ChartFactory.createLineChart("Block Cipher Encryption Times", "File Size (bytes)", "Time (ms)",
                datasetEncryption, PlotOrientation.VERTICAL, true, true, false);

        JFreeChart decryptionChart = ChartFactory.createLineChart("Block Cipher Decryption Times", "File Size (bytes)", "Time (ms)",
                datasetDecryption, PlotOrientation.VERTICAL, true, true, false);

        ChartFrame frame1 = new ChartFrame("Encryption Times", encryptionChart);
        frame1.setVisible(true);
        frame1.setSize(800, 600);

        ChartFrame frame2 = new ChartFrame("Decryption Times", decryptionChart);
        frame2.setVisible(true);
        frame2.setSize(800, 600);

    }

    public static byte[] generateRandomData(int size) {
        byte[] data = new byte[size];
        new java.util.Random().nextBytes(data);
        return data;
    }

    public static byte[] generateRandomData(int minSize, int maxSize) {
        int size = minSize + new java.util.Random().nextInt(maxSize - minSize);
        return generateRandomData(size);
    }

    public static long[] encryptAndDecrypt(SecretKeySpec key, Path inputFile, String cipherAlgorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        long startTimeEncryption = System.currentTimeMillis();
        byte[] encryptedData = cipher.doFinal(Files.readAllBytes(inputFile));
        long endTimeEncryption = System.currentTimeMillis();

        cipher.init(Cipher.DECRYPT_MODE, key);

        long startTimeDecryption = System.currentTimeMillis();
        byte[] decryptedData = cipher.doFinal(encryptedData);
        long endTimeDecryption = System.currentTimeMillis();

        if (!Arrays.equals(Files.readAllBytes(inputFile), decryptedData)) {
            throw new RuntimeException("Decrypted data doesn't match original data");
        }

        return new long[] {endTimeEncryption - startTimeEncryption, endTimeDecryption - startTimeDecryption};
    }

    public static long[] encryptAndDecrypt(SecretKeySpec key, IvParameterSpec iv, Path inputFile, String cipherAlgorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        long startTimeEncryption = System.currentTimeMillis();
        byte[] encryptedData = cipher.doFinal(Files.readAllBytes(inputFile));
        long endTimeEncryption = System.currentTimeMillis();

        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        long startTimeDecryption = System.currentTimeMillis();
        byte[] decryptedData = cipher.doFinal(encryptedData);
        long endTimeDecryption = System.currentTimeMillis();

        if (!Arrays.equals(Files.readAllBytes(inputFile), decryptedData)) {
            throw new RuntimeException("Decrypted data doesn't match original data");
        }

        return new long[] {endTimeEncryption - startTimeEncryption, endTimeDecryption - startTimeDecryption};
    }
}