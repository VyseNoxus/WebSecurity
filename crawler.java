package web_crawler;

import java.awt.*;
import javax.swing.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

public class crawler {

	private JFrame frame;
    private JTextField urlField, usernameField, passwordField, depthField;
    private JTextArea resultArea;
    private JButton startButton, loginButton, exportButton;
    private Map<String, String> cookies;
    private String storedUsername, storedPassword;
    
    private Set<String> idorParameters = new HashSet<>();
    private List<String> idorEntries = new ArrayList<>();
    
    public crawler() {
        frame = new JFrame("IDOR Guard");
        frame.setSize(600, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(7, 2, 5, 5));
        
        urlField = new JTextField("http://test2214.sytes.net/index.php", 25);
        usernameField = new JTextField(15);
        passwordField = new JPasswordField(15);
        depthField = new JTextField("3", 3);
        startButton = new JButton("Start Crawling");
        loginButton = new JButton("Login");
        exportButton = new JButton("Export log");
        
        panel.add(new JLabel("URL:")); panel.add(urlField);
        panel.add(new JLabel("Username:")); panel.add(usernameField);
        panel.add(new JLabel("Password:")); panel.add(passwordField);
        panel.add(new JLabel("Depth:")); panel.add(depthField);
        panel.add(loginButton); 
        panel.add(startButton);
        panel.add(exportButton);
        
        resultArea = new JTextArea();
        resultArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(resultArea);
        
        frame.add(panel, BorderLayout.NORTH);
        frame.add(scrollPane, BorderLayout.CENTER);
        
        loginButton.addActionListener(e -> login());
        startButton.addActionListener(e -> startCrawl());
        exportButton.addActionListener(e -> exportLog());
        
        frame.setVisible(true);
        
        loadDictionary("parameters.txt");
    }
    
    private void login() {
    	if (!usernameField.getText().isEmpty() && !passwordField.getText().isEmpty()) {
            try {
                Connection.Response response = Jsoup.connect(urlField.getText())
                        .data("username", usernameField.getText())
                        .data("password", passwordField.getText())
                        .method(Connection.Method.POST)
                        .execute();
                
                // Store cookies and credentials
                cookies = response.cookies();
                storedUsername = usernameField.getText();
                storedPassword = passwordField.getText();
                
                // Check for successful login
                if (cookies.isEmpty() || response.body().contains("Invalid username or password")) {
                    SwingUtilities.invokeLater(() -> resultArea.append("Login failed! Check credentials.\n"));
                } else {
                    SwingUtilities.invokeLater(() -> resultArea.append("Login successful!\n"));
                }
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> resultArea.append("Login request failed!\n"));
            }
        } else {
            SwingUtilities.invokeLater(() -> resultArea.append("Both username and password must be provided, skipping login.\n"));
        }
    }
    
    private void startCrawl() {
        resultArea.setText("");
        
        String url = urlField.getText();
        int depth;
        try {
            depth = Integer.parseInt(depthField.getText());
        } catch (NumberFormatException ex) {
            resultArea.setText("Invalid depth value.\n");
            return;
        }
        
        new Thread(() -> crawl(1, url, depth, new ArrayList<>())).start();
    }
    
    
    private void crawl(int level, String url, int maxDepth, ArrayList<String> visited) {
        if (level > maxDepth || visited.contains(url)) {
            return;
        }
        
        Document doc = request(url, visited);
        if (doc != null) {
        	testIDOR(url);
            for (Element link : doc.select("a[href]")) {
                String nextLink = link.absUrl("href");
                crawl(level + 1, nextLink, maxDepth, visited);
            }
        }
    }
    
    private Document request(String url, ArrayList<String> visited) {
        try {
            Connection con = Jsoup.connect(url);
            
            if (cookies != null && !cookies.isEmpty()) {
                con.cookies(cookies);  // Include cookies if login was successful
            }
            
            Document doc = con.get();
            if (con.response().statusCode() == 200) {
                SwingUtilities.invokeLater(() -> {
                    resultArea.append("Link: " + url + "\n");
                    resultArea.append(doc.title() + "\n\n");
                });
                visited.add(url);

                // Search for sensitive parameters in the page
                searchForSensitiveParameters(doc, url);
                
                // Check for login form and attempt to log in if found
                if (doc.select("input[name=username]").size() > 0 && doc.select("input[name=password]").size() > 0) {
                	SwingUtilities.invokeLater(() -> resultArea.append("Login form detected, attempting to auto-login at: " + url + "\n"));
                    
                    // Attempt to log in with stored credentials
                	if (storedUsername != null && storedPassword != null) {
                        try {
                            Connection.Response loginResponse = Jsoup.connect(url)
                                    .data("username", storedUsername)
                                    .data("password", storedPassword)
                                    .method(Connection.Method.POST)
                                    .cookies(cookies)  // Keep existing session
                                    .followRedirects(true)
                                    .execute();
                            
                            cookies.putAll(loginResponse.cookies());  // Update cookies
                            
                            // Get the redirected page
                            String redirectedUrl = loginResponse.url().toString();
                            
                            if(!redirectedUrl.equals(url)) {
                            SwingUtilities.invokeLater(() -> resultArea.append("Redirected to: " + redirectedUrl + "\n"));
                            
                            // Fetch the new page after login
                            return Jsoup.connect(redirectedUrl).cookies(cookies).get();
                            }
                            else {
                            	SwingUtilities.invokeLater(() -> resultArea.append("login failed. Please check the login again.\n"));
                            }
                            
                        } catch (IOException e) {
                            SwingUtilities.invokeLater(() -> resultArea.append("Auto-login failed at: " + url + "\n"));
                        }
                    }
                }
                
                return doc;
            }
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("Failed to fetch: " + url + "\n"));
        }
        return null;
    }
    
    private String getHttpResponse(String url) throws IOException {
        Connection con = Jsoup.connect(url);
        
        if (cookies != null && !cookies.isEmpty()) {
            con.cookies(cookies); // **Use session cookies to access restricted pages**
        }

        return con.get().text();
    }

    private void checkResponse(String testUrl, String originalResponse) throws IOException {
        String testResponse = getHttpResponse(testUrl);
        if (!originalResponse.equals(testResponse) && !testResponse.toLowerCase().contains("user not found")) {
        	String logEntry = "[!] Possible IDOR detected: " + testUrl;
            SwingUtilities.invokeLater(() -> {
                resultArea.append(logEntry + "\n");
                idorEntries.add(logEntry); // Add to IDOR entries list
            });
        } else {
            SwingUtilities.invokeLater(() -> resultArea.append("[*] No valid data at: " + testUrl + "\n"));
        }
    }
    
    private void testIDOR(String url) {
        if (!url.contains("?")) {
            return;
        }

        try {
            String originalResponse = getHttpResponse(url);
            String[] parts = url.split("\\?");
            if (parts.length < 2) {
                return;
            }
            String base = parts[0];
            String query = parts[1];

            String[] params = query.split("&");

            for (String param : params) {
                String[] kv = param.split("=");
                if (kv.length != 2) {
                    continue;
                }

                String key = kv[0].toLowerCase();
                String originalValue = kv[1];

                if (idorParameters.contains(key)) { // **Only test parameters in dictionary**
                    SwingUtilities.invokeLater(() -> resultArea.append("[+] Testing IDOR on: " + key + "\n"));

                    for (int i = 1; i <= 10; i++) {
                        String testUrl = base + "?" + key + "=" + i;

                        for (String otherParam : params) {
                            if (!otherParam.startsWith(key + "=")) {
                                testUrl += "&" + otherParam;
                            }
                        }

                        checkResponse(testUrl, originalResponse);
                    }
                }
            }
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("Error testing IDOR for: " + url + "\n"));
        }
    }

    private void searchForSensitiveParameters(Document doc, String url) {
        for (String param : idorParameters) {
            boolean found = false;


            // Search for parameter inside forms and log the form's name or ID
            for (Element form : doc.select("form")) {
                if (form.html().contains(param)) {
                    String formIdentifier = form.id().isEmpty() ? (form.attr("name").isEmpty() ? "Unnamed Form" : form.attr("name")) : form.id();

                    // Look for parent div ID
                    Element parentDiv = form.parent();
                    while (parentDiv != null && !parentDiv.tagName().equals("div")) {
                        parentDiv = parentDiv.parent(); // Move up the DOM until a <div> is found
                    }
                    String parentDivId = (parentDiv != null && !parentDiv.id().isEmpty()) ? parentDiv.id() : "No Parent Div";

                    String logEntry = "[!] Found " + param + " inside form: " + formIdentifier + ", Parent Div: " + parentDivId + ")";
                    SwingUtilities.invokeLater(() -> resultArea.append(logEntry + "\n"));
                    idorEntries.add(logEntry);
                    found = true;
                }
            }

            // Search for parameter name in input fields, elements, and attributes
            for (Element element : doc.getAllElements()) {
                if (element.attr("name").equalsIgnoreCase(param) ||
                        element.attr("id").equalsIgnoreCase(param) ||
                        element.text().contains(param)) {

                    String logEntry = "[!] Found " + param + " in " + (element.attr("name").isEmpty() ? element.attr("id") : element.attr("name")) + url;
                    SwingUtilities.invokeLater(() -> resultArea.append(logEntry + "\n"));
                    idorEntries.add(logEntry);
                    found = true;
                }
            }

            // Search for direct text occurrences in page content
            if (doc.text().toLowerCase().contains(param.toLowerCase())) {
                String logEntry = "[!] Found " + param + " in page text at " + url;
                SwingUtilities.invokeLater(() -> resultArea.append(logEntry + "\n"));
                idorEntries.add(logEntry);
                found = true;
            }
        }
    }

    private void loadDictionary(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                idorParameters.add(line.trim().toLowerCase());
            }
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("[-] Error loading dictionary file.\n"));
        }
    }
    
    public void exportLog() {
        if (idorEntries.isEmpty()) {
            SwingUtilities.invokeLater(() -> resultArea.append("[-] No IDOR vulnerabilities detected, nothing to export.\n"));
            return;
        }

        try (FileWriter writer = new FileWriter("IDOR_Report.csv")) {
            // Write CSV header
            writer.append("IDOR Detected,Recommendation\n");

            // Write only entries that contain "Possible IDOR detected"
            for (String entry : idorEntries) {
                if (entry.contains("Possible IDOR detected")) {
                    writer.append("\"").append(entry).append("\",");
                    writer.append("\"Implement proper access control: Ensure users can only access their own data. Use Role-Based Access Control (RBAC).\"\n"); // Default recommendation
                }
            }

            SwingUtilities.invokeLater(() -> resultArea.append("[+] IDOR report exported successfully to IDOR_Report.csv\n"));
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("[-] Error exporting IDOR report: " + e.getMessage() + "\n"));
        }
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(crawler::new);
    }

}
