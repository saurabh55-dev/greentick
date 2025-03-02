package com.saurabh;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebCrawler {

    private final Set<String> visitedLinks = new HashSet<>();

    public void crawl(String url){
        if(visitedLinks.contains(url)){
            return;
        }
        visitedLinks.add(url);
        try{
            Document document = Jsoup.connect(url).get();
            checkSecurityHeaders(url);
            checkSoftwareVersion(url);
            checkFormsForSecurity(document, url);

            Elements links = document.select("a[href]");
            for(Element link : links){
                String nextUrl = link.absUrl("href");
                if(nextUrl.startsWith("http")){
                    crawl(nextUrl);
                }
            }
        }catch(IOException e){
            System.out.println("Failed to access: " + url);
        }
    }
    private void checkSecurityHeaders(String url){
        try{
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("GET");
            connection.connect();

            String[] headersToCheck = {"Strict-Transport-Security", "X-Content-Type-Options"};
            for(String header : headersToCheck){
                if(connection.getHeaderField(header) == null){
                    System.out.println("[VULNERABILITY] " + header + " is missing on " + url);
                }
            }
        }catch(IOException e){
            System.out.println("Could not check security headers for: " + url);
        }
    }
    private void checkSoftwareVersion(String url) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("GET");
            connection.connect();

            String serverHeader = connection.getHeaderField("Server");
            if (serverHeader != null) {
                System.out.println("[INFO] Server Header Detected: " + serverHeader);
                checkOutdatedSoftware(serverHeader, url);
            }
        } catch (IOException e) {
            System.out.println("Could not check software version for: " + url);
        }
    }
    private void checkOutdatedSoftware(String serverHeader, String url) {
        // Example pattern: Apache/2.4.6
        Pattern pattern = Pattern.compile("(Apache|Nginx|IIS)/(\\d+\\.\\d+\\.\\d+)");
        Matcher matcher = pattern.matcher(serverHeader);

        if (matcher.find()) {
            String software = matcher.group(1);
            String version = matcher.group(2);

            // Example: Flagging Apache 2.4.6 as outdated
            if (software.equalsIgnoreCase("Apache") && version.equals("2.4.6")) {
                System.out.println("[VULNERABILITY] OUTDATED SOFTWARE VERSION DETECTED: " + software + " " + version + " on " + url);
            }
        }
    }

    private void checkFormsForSecurity(Document document, String url){
        Elements forms = document.select("form");
        for(Element form : forms){
            String action = form.attr("action");
            String method = form.attr("method");

            if(action.isEmpty()){
                System.out.println("[VULNERABILITY] Form with missing action attribute found on " + url);
            }
            if(!method.equals("POST")){
                System.out.println("[VULNERABILITY] Form using GET method found on " + url);
            }
        }
    }
    public static void main(String[] args) {
        String startUrl = "http://www.example.com";        //target url
        WebCrawler crawler = new WebCrawler();
        crawler.crawl(startUrl);
    }
}
