package com.saurabh;

import java.io.*;
import java.util.Scanner;

public class SystemMonitor
{
    public static void main( String[] args )
    {
        //creating a log file and writing in it for testing purpose
        File file = new File("log.txt");
        try {
            //file.createNewFile();
            FileWriter writer = new FileWriter("log.txt");
            writer.write("User requested login form.\nfailed LOGIN");
            writer.close();
        } catch (IOException e) {
            System.out.println("File not created: " + e.getMessage());
        }
        // Invoking logReader function to read the log file
        System.out.println(logReader(file));
    }

    // Function to read the file and identify any suspicious patterns
    private static String logReader(File file){
        StringBuilder result = new StringBuilder();
        try {
            Scanner scanner = new Scanner(file);
            while(scanner.hasNextLine()){
                String line = scanner.nextLine().toLowerCase();
                if(line.contains("failed login")){
                    result.append("ALERT: 'FAILED LOGIN' DETECTED!!");
                }
                if(line.contains("unauthorized access")){
                    result.append("ALERT: 'UNAUTHORIZED ACCESS' DETECTED!!");
                }
                if(line.contains("malicious activity detected")){
                    result.append("ALERT: 'MALICIOUS ACTIVITY DETECTED' DETECTED!!");
                }
            }
            scanner.close();
        } catch (IOException e) {
            System.out.println("Error reading logFile: " + file.getName());
        }
        if(result.isEmpty()) return "Nothing detected. ITS SAFE!!";
        return result.toString();
    }
}
